// tattle worker: the off-box half. Machines can append reports here and do
// nothing else. Alerts on suspicious change, on silence, and on canary trips.
//
// Bindings (see wrangler.toml.example):
//   REPORTS     R2 bucket, write-once reports
//   STATE       KV namespace: last report + last-seen per host
//   HOST_TOKENS secret, JSON {"<sha256 hex of token>": "<host name>", ...}
//   READ_TOKEN  secret, bearer token for GET /reports (the analyzer)
//   CANARY_KEY  secret, shared key in the canary webhook URL
//   EMAIL       optional send_email binding, with vars ALERT_EMAIL_FROM (an
//               address on a domain using Cloudflare Email Routing) and
//               ALERT_EMAIL_TO (a verified destination). Gets every alert.
//   NTFY_URL    optional secret, e.g. https://ntfy.sh/<long random topic>.
//               Gets canary trips, or every alert when email isn't configured.
//   STALE_HOURS var, default 36
//   HEARTBEAT_URL optional secret: pinged every cron run, so an outside
//               dead-man's switch (e.g. healthchecks.io) notices if this
//               worker is deleted or stops running.
//   NTFY_TOKEN  optional secret: ntfy access token, for a reserved topic or
//               a self-hosted server.
//   CANARY_EMAIL  optional var: canarytokens.org also emails trips here.

import collectorScript from "../../collector/tattle-collect";
import installScript from "../../collector/install.sh";
import { diffSections } from "./diff.js";
import { mintCanaries, plantScript } from "./canaries.js";
import { alertMime } from "./email.js";

const MAX_BODY = 2 * 1024 * 1024; // decompressed
const MIN_INTERVAL_MS = 3600 * 1000; // one report per host per hour

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		try {
			if (request.method === "POST" && url.pathname === "/ingest") return await ingest(request, env);
			if (request.method === "POST" && url.pathname === "/canary") return await canary(request, env, url);
			if (request.method === "GET" && url.pathname === "/reports") return await listReports(request, env, url);
			if (request.method === "GET" && url.pathname === "/report") return await getReport(request, env, url);
			if (request.method === "GET" && url.pathname === "/hosts") return await listHosts(request, env);
			if (request.method === "GET" && url.pathname === "/canaries.sh") return await canariesScript(request, env, url);
			if (request.method === "GET" && url.pathname === "/tattle-collect") return text(collectorScript);
			if (request.method === "GET" && url.pathname === "/install.sh") return text(installScript.replace("__TATTLE_URL__", url.origin));
		} catch (err) {
			console.error(err);
			return new Response("error\n", { status: 500 });
		}
		return new Response("not found\n", { status: 404 });
	},

	async scheduled(_event, env) {
		await checkSilence(env);
		if (env.HEARTBEAT_URL) await fetch(env.HEARTBEAT_URL).catch((err) => console.error("heartbeat failed", err));
	},
};

// ---------------------------------------------------------------- ingest

async function ingest(request, env) {
	const host = await hostForToken(request, env);
	if (!host) return new Response("unauthorized\n", { status: 401 });

	// A compromised host must not be able to burn the KV write or ntfy quotas
	// that every other host's alerts depend on.
	const now = new Date();
	const seen = (await env.STATE.get(`seen/${host}`, "json")) || {};
	if (seen.at && now - Date.parse(seen.at) < MIN_INTERVAL_MS) return new Response("too soon\n", { status: 429 });

	const report = await readReport(request);
	if (!report) return new Response("bad report\n", { status: 400 });

	const key = `reports/${host}/${now.toISOString()}-${crypto.randomUUID().slice(0, 8)}.json`;
	const body = JSON.stringify({ ...report, host, receivedAt: now.toISOString() });
	await env.REPORTS.put(key, body, { httpMetadata: { contentType: "application/json" } });

	// Alert before saving the new baseline: if ntfy fails, this request fails,
	// the collector retries, and the same change is found again.
	const previous = await env.STATE.get(`last/${host}`, "json");
	if (previous) {
		const findings = diffSections(previous, report.sections);
		if (findings.length) {
			await notify(env, `${host}: ${findings.length} security-relevant change${findings.length > 1 ? "s" : ""}`, findings.slice(0, 20).join("\n"), {
				priority: 4,
				tags: "warning",
			});
		}
	}
	if (seen.staleAlertedAt) await notify(env, `${host} is reporting again`, "It had gone quiet.", { priority: 3, tags: "white_check_mark" });

	await env.STATE.put(`last/${host}`, JSON.stringify(report.sections));
	await env.STATE.put(`seen/${host}`, JSON.stringify({ at: now.toISOString(), staleAlertedAt: null }));
	return new Response("ok\n");
}

async function readReport(request) {
	if (!request.body) return null;
	let stream = request.body;
	if ((request.headers.get("content-type") || "").includes("gzip")) {
		stream = stream.pipeThrough(new DecompressionStream("gzip"));
	}
	// Count decompressed bytes as they arrive, so neither a missing
	// Content-Length nor a gzip bomb gets past the limit.
	let total = 0;
	stream = stream.pipeThrough(
		new TransformStream({
			transform(chunk, controller) {
				total += chunk.byteLength;
				if (total > MAX_BODY) controller.error(new Error("report too large"));
				else controller.enqueue(chunk);
			},
		}),
	);
	let text;
	try {
		text = await new Response(stream).text();
	} catch {
		return null;
	}
	let report;
	try {
		report = JSON.parse(text);
	} catch {
		return null;
	}
	if (!report || typeof report.sections !== "object") return null;
	return report;
}

// ---------------------------------------------------------------- silence

async function checkSilence(env) {
	const staleMs = Number(env.STALE_HOURS || 36) * 3600 * 1000;
	const now = Date.now();
	let cursor;
	do {
		const page = await env.STATE.list({ prefix: "seen/", cursor });
		for (const { name } of page.keys) {
			const host = name.slice("seen/".length);
			const seen = await env.STATE.get(name, "json");
			if (!seen) continue;
			const quietFor = now - Date.parse(seen.at);
			if (quietFor < staleMs) continue;
			// Remind once a day, not every hour.
			if (seen.staleAlertedAt && now - Date.parse(seen.staleAlertedAt) < 24 * 3600 * 1000) continue;
			const hours = Math.round(quietFor / 3600000);
			await notify(env, `${host} has not reported for ${hours}h`, `Last report ${seen.at}. Check the machine is up and the collector still runs.`, {
				priority: 4,
				tags: "mute",
			});
			await env.STATE.put(name, JSON.stringify({ ...seen, staleAlertedAt: new Date(now).toISOString() }));
		}
		cursor = page.list_complete ? undefined : page.cursor;
	} while (cursor);
}

// ---------------------------------------------------------------- canaries

async function canary(request, env, url) {
	if (!env.CANARY_KEY || !timingSafeEqual(url.searchParams.get("key") || "", env.CANARY_KEY)) {
		return new Response("unauthorized\n", { status: 401 });
	}
	const text = await request.text();
	let memo = "", detail = text.slice(0, 1500);
	try {
		const hit = JSON.parse(text);
		memo = hit.memo || "";
		detail = [hit.channel, hit.src_ip && `from ${hit.src_ip}`, hit.time, hit.additional_data && JSON.stringify(hit.additional_data).slice(0, 800)]
			.filter(Boolean)
			.join("\n");
	} catch {
		// canarytokens.org may send form-encoded bodies; keep the raw text.
	}
	// canarytokens.org pings every new webhook once to prove it works.
	if (/newly saved webhook works/i.test(memo)) return new Response("ok\n");
	await notify(env, `CANARY TRIPPED ${memo}`.trim(), detail || "A canary token was used.", { priority: 5, tags: "rotating_light", push: true });
	return new Response("ok\n");
}

async function canariesScript(request, env, url) {
	const host = await hostForToken(request, env);
	if (!host) return new Response("unauthorized\n", { status: 401 });
	const user = (url.searchParams.get("user") || "user").replace(/[^a-z0-9._-]/gi, "");
	return text(plantScript(await mintCanaries(env, url.origin, `${host} (${user})`)));
}

// ---------------------------------------------------------------- read API

async function listReports(request, env, url) {
	if (!authorizedReader(request, env)) return new Response("unauthorized\n", { status: 401 });
	const host = url.searchParams.get("host");
	const prefix = host ? `reports/${host}/` : "reports/";
	const since = url.searchParams.get("since") || "";
	const keys = [];
	let cursor;
	do {
		const page = await env.REPORTS.list({ prefix, cursor, limit: 1000 });
		for (const obj of page.objects) {
			const stamp = obj.key.split("/").pop();
			if (!since || stamp >= since) keys.push(obj.key);
		}
		cursor = page.truncated ? page.cursor : undefined;
	} while (cursor);
	return Response.json({ keys });
}

async function getReport(request, env, url) {
	if (!authorizedReader(request, env)) return new Response("unauthorized\n", { status: 401 });
	const key = url.searchParams.get("key") || "";
	if (!key.startsWith("reports/")) return new Response("bad key\n", { status: 400 });
	const obj = await env.REPORTS.get(key);
	if (!obj) return new Response("not found\n", { status: 404 });
	return new Response(obj.body, { headers: { "content-type": "application/json" } });
}

async function listHosts(request, env) {
	if (!authorizedReader(request, env)) return new Response("unauthorized\n", { status: 401 });
	const hosts = {};
	let cursor;
	do {
		const page = await env.STATE.list({ prefix: "seen/", cursor });
		for (const { name } of page.keys) hosts[name.slice(5)] = await env.STATE.get(name, "json");
		cursor = page.list_complete ? undefined : page.cursor;
	} while (cursor);
	return Response.json({ hosts });
}

// ---------------------------------------------------------------- helpers

function text(body) {
	return new Response(body, { headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
}

async function hostForToken(request, env) {
	const token = bearer(request);
	if (!token) return null;
	const tokens = JSON.parse(env.HOST_TOKENS || "{}");
	return tokens[await sha256(token)] || null;
}

function authorizedReader(request, env) {
	const token = bearer(request);
	return Boolean(env.READ_TOKEN && token && timingSafeEqual(token, env.READ_TOKEN));
}

function bearer(request) {
	const h = request.headers.get("authorization") || "";
	return h.startsWith("Bearer ") ? h.slice(7).trim() : null;
}

async function sha256(text) {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
	return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a, b) {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return diff === 0;
}

// Every alert goes to email when it is configured. ntfy is optional: if it is
// set up, canary trips also go there as a phone push, and it takes every alert
// when email isn't configured.
async function notify(env, title, message, { priority = 3, tags = "", push = false } = {}) {
	const email = Boolean(env.EMAIL && env.ALERT_EMAIL_FROM && env.ALERT_EMAIL_TO);
	const sends = [];
	if (email) sends.push(sendEmail(env, title, message));
	if (env.NTFY_URL && (push || !email)) sends.push(sendPush(env, title, message, priority, tags));
	if (!sends.length) return console.log("no alert channel configured:", title, message);
	const results = await Promise.allSettled(sends);
	const errors = results.filter((r) => r.status === "rejected").map((r) => r.reason?.message || String(r.reason));
	// One channel getting through is enough. If none did, throw, so the
	// caller's request fails and gets retried instead of the alert being lost.
	if (errors.length === results.length) throw new Error(errors.join("; "));
	for (const e of errors) console.error("alert channel failed:", e);
}

async function sendEmail(env, title, message) {
	const { EmailMessage } = await import("cloudflare:email");
	const raw = alertMime({ from: env.ALERT_EMAIL_FROM, to: env.ALERT_EMAIL_TO, subject: title, body: message });
	await env.EMAIL.send(new EmailMessage(env.ALERT_EMAIL_FROM, env.ALERT_EMAIL_TO, raw));
}

async function sendPush(env, title, message, priority, tags) {
	const headers = { Title: title.replace(/[\r\n]+/g, " ").slice(0, 200), Priority: String(priority), Tags: tags };
	if (env.NTFY_TOKEN) headers.Authorization = `Bearer ${env.NTFY_TOKEN}`;
	const res = await fetch(env.NTFY_URL, { method: "POST", body: message.slice(0, 3800), headers });
	if (!res.ok) throw new Error(`ntfy failed: ${res.status} ${await res.text()}`);
}
