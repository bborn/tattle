import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createWorker, HostGate } from "../src/runtime.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
const worker = createWorker({ collectorScript: "collector", installScript: "url='__TATTLE_URL__'\n" });
const TOKEN = "host-secret";
const HOST = "laptop";
const hash = async (s) => Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))).toString("hex");
const report = (sections = { accounts: "alice", posture: "safe", listening: "" }) => ({ version: 1, os: "linux", collectedAt: "2026-10-26T00:00:00Z", sections });
const clone = (x) => x === undefined ? undefined : structuredClone(x);
class Storage {
	constructor() { this.map = new Map(); this.writes = 0; }
	async get(k) { return clone(this.map.get(k)); }
	async put(k, v) { this.writes++; this.map.set(k, clone(v)); }
	async delete(k) { this.map.delete(k); }
	async transaction(fn) {
		const before = clone(this.map);
		try { return await fn(this); } catch (err) { this.map = before; throw err; }
	}
}
class KV {
	constructor() { this.map = new Map(); this.writes = 0; this.listCalls = 0; this.failPut = null; this.failGet = new Set(); }
	async get(k) { if (this.failGet.has(k)) throw Error("KV unavailable"); return this.map.has(k) ? JSON.parse(this.map.get(k)) : null; }
	async put(k, v) { if (this.failPut?.(k)) throw Error("KV put failed"); this.writes++; this.map.set(k, v); }
	async delete(k) { this.writes++; this.map.delete(k); }
	async list({ prefix, cursor, limit = 1000 }) {
		this.listCalls++;
		const keys = [...this.map.keys()].filter((k) => k.startsWith(prefix)).sort();
		const start = Number(cursor || 0), names = keys.slice(start, start + limit);
		return { keys: names.map((name) => ({ name })), list_complete: start + limit >= keys.length, cursor: String(start + limit) };
	}
}
class Bucket {
	constructor() { this.map = new Map(); this.puts = 0; this.listCalls = 0; this.failAfterPut = false; }
	async head(k) { return this.map.has(k) ? { key: k } : null; }
	async put(k, v, opts) {
		assert.deepEqual(opts.onlyIf, { etagDoesNotMatch: "*" });
		if (this.map.has(k)) throw Error("retention lock forbids overwrite");
		this.puts++; this.map.set(k, v);
		if (this.failAfterPut) { this.failAfterPut = false; throw Error("lost R2 acknowledgement"); }
		return { key: k };
	}
	async get(k) { const value = this.map.get(k); return value ? { body: value, json: async () => JSON.parse(value) } : null; }
	async list({ prefix, cursor, limit }) {
		this.listCalls++;
		const keys = [...this.map.keys()].filter((k) => k.startsWith(prefix)).sort();
		const start = Number(cursor || 0);
		return { objects: keys.slice(start, start + limit).map((key) => ({ key })), truncated: start + limit < keys.length, cursor: String(start + limit) };
	}
}
async function environment(hosts = [HOST]) {
	const env = { STATE: new KV(), REPORTS: new Bucket(), HOST_TOKENS: JSON.stringify(Object.fromEntries(await Promise.all(hosts.map(async (host, i) => [await hash(i ? `token-${i}` : TOKEN), host])))), READ_TOKEN: "reader", CANARY_KEY: "fleet-secret", NTFY_URL: "https://notify.test/topic", STALE_HOURS: "36" };
	const objects = new Map(), stores = new Map();
	env.HOST_GATE = {
		idFromName: (host) => host,
		get(host) {
			if (!stores.has(host)) stores.set(host, new Storage());
			if (!objects.has(host)) objects.set(host, new HostGate({ storage: stores.get(host) }, env));
			return objects.get(host);
		},
	};
	env.stores = stores;
	env.restart = () => objects.clear();
	env.store = async (_token = TOKEN, host = HOST) => stores.get(host);
	return env;
}
function req(path, body, token = TOKEN, headers = {}) {
	return new Request(`https://tattle.test${path}`, { method: body === undefined ? "GET" : "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...headers }, ...(body === undefined ? {} : { body: typeof body === "string" ? body : JSON.stringify(body) }) });
}
async function seed(env, host = HOST, data = { accounts: "alice", posture: "safe", listening: "" }) {
	env.STATE.map.set(`last/${host}`, JSON.stringify(data));
	env.STATE.map.set(`seen/${host}`, JSON.stringify({ at: "2020-01-01T00:00:00Z", staleAlertedAt: null }));
}
async function withFetch(fn, run) { const previous = globalThis.fetch; globalThis.fetch = fn; try { await run(); } finally { globalThis.fetch = previous; } }

// These cases deliberately inspect both durable admission and archive writes.
test("strict host gate serializes simultaneous reports and preserves server identity", async () => {
	const env = await environment(); await seed(env);
	let notifications = 0;
	await withFetch(async () => { notifications++; await new Promise((r) => setTimeout(r, 10)); return new Response("ok"); }, async () => {
		const data = { ...report({ accounts: "alice\nevil" }), host: "forged", receivedAt: "2000-01-01T00:00:00Z" };
		const results = await Promise.all(Array.from({ length: 12 }, () => worker.fetch(req("/ingest", data), env)));
		assert.equal(results.filter((r) => r.status === 200).length, 1);
		assert.equal(results.filter((r) => r.status === 429).length, 11);
		assert.equal(notifications, 1); assert.equal(env.REPORTS.puts, 1);
		const stored = JSON.parse([...env.REPORTS.map.values()][0]);
		assert.equal(stored.host, HOST); assert.notEqual(stored.receivedAt, data.receivedAt);
	});
});

test("gate binding absence fails closed before any writes", async () => {
	const env = await environment(); delete env.HOST_GATE;
	const res = await worker.fetch(req("/ingest", report()), env);
	assert.equal(res.status, 503); assert.match(await res.text(), /HOST_GATE.*binding/);
	assert.equal(env.REPORTS.puts + env.STATE.writes, 0);
});

test("notification failure retries stable archive and bounds hostile repeated attempts", async () => {
	const env = await environment(); await seed(env);
	let count = 0;
	await withFetch(async () => { count++; return new Response("down", { status: 500 }); }, async () => {
		for (let i = 0; i < 8; i++) {
			const res = await worker.fetch(req("/ingest", report({ accounts: "evil" })), env);
			assert.equal(res.status, i < 6 ? 503 : 429);
		}
		assert.equal(env.REPORTS.puts, 1); assert.equal(env.REPORTS.map.size, 1); assert.equal(count, 6);
		assert.equal((await env.STATE.get(`seen/${HOST}`)).at, "2020-01-01T00:00:00Z");
	});
});

test("state failure after delivered alert retries KV without duplicate alert/archive", async () => {
	const env = await environment(); await seed(env);
	let count = 0;
	env.STATE.failPut = (key) => key.startsWith("seen/");
	await withFetch(async () => { count++; return new Response("ok"); }, async () => {
		const data = report({ accounts: "evil" });
		assert.equal((await worker.fetch(req("/ingest", data), env)).status, 503);
		env.restart(); env.STATE.failPut = null;
		assert.equal((await worker.fetch(req("/ingest", data), env)).status, 200);
		assert.equal(count, 1); assert.equal(env.REPORTS.puts, 1);
	});
});

test("pending report survives interrupted R2 acknowledgement and conflicting reports", async () => {
	const env = await environment(); env.REPORTS.failAfterPut = true;
	const data = report();
	assert.equal((await worker.fetch(req("/ingest", data), env)).status, 503);
	env.restart();
	assert.equal((await worker.fetch(req("/ingest", data), env)).status, 200);
	assert.equal(env.REPORTS.puts, 1);
});

test("in-flight lease recovers after expiry without accepting competing archive", async () => {
	const env = await environment();
	await worker.fetch(req("/ingest", report()), env);
	const store = await env.store();
	const key = [...env.REPORTS.map.keys()][0];
	const payloadHash = await hash(JSON.stringify(report()));
	store.map.set("reportState", { pending: { fingerprint: payloadHash, key, receivedAt: new Date().toISOString(), archived: true, notifications: [], nextNotification: 0, chunks: 1, leaseUntil: Date.now() + 10000 } });
	store.map.set("pendingBody/0", new TextEncoder().encode(JSON.stringify(report())));
	env.restart();
	assert.equal((await worker.fetch(req("/ingest", report()), env)).status, 503);
	store.map.get("reportState").pending.leaseUntil = Date.now() - 1;
	assert.equal((await worker.fetch(req("/ingest", report()), env)).status, 200);
	assert.equal(env.REPORTS.puts, 1);
});

test("schema poison returns controlled 400 and zero writes including durable state", async () => {
	const poisons = [null, [], "text", { sections: null }, { sections: [] }, { sections: { accounts: {} } }, report({ accounts: ["x"] }), report({ constructor: "bad" }), { ...report(), version: {} }, { ...report(), os: [] }, { ...report(), collectedAt: "bad" }, { ...report(), extra: "bad" }, JSON.parse('{"version":1,"os":"linux","collectedAt":"2026-10-26T00:00:00Z","sections":{"__proto__":"bad"}}')];
	for (const poison of poisons) {
		const env = await environment();
		const res = await worker.fetch(req("/ingest", JSON.stringify(poison)), env);
		assert.equal(res.status, 400, JSON.stringify(poison).slice(0, 150));
		assert.equal(env.STATE.writes + env.REPORTS.puts, 0);
		assert.equal([...env.stores.values()].reduce((n, s) => n + s.writes, 0), 0);
	}
});

test("forward-compatible string sections work and exact 2 MiB decompressed limit is enforced", async () => {
	const env = await environment();
	const data = report({ accounts: "", future_probe: "" });
	const overhead = Buffer.byteLength(JSON.stringify(data));
	const remaining = 2 * 1024 * 1024 - overhead;
	data.sections.accounts = "a".repeat(Math.floor(remaining / 2));
	data.sections.future_probe = "b".repeat(remaining - data.sections.accounts.length);
	assert.equal(Buffer.byteLength(JSON.stringify(data)), 2 * 1024 * 1024);
	assert.equal((await worker.fetch(req("/ingest", data), env)).status, 200);
	const env2 = await environment(); data.sections.accounts += "a";
	assert.equal((await worker.fetch(req("/ingest", data), env2)).status, 413);
	assert.equal(env2.STATE.writes + env2.REPORTS.puts, 0);
	const stream = new Blob([JSON.stringify(data)]).stream().pipeThrough(new CompressionStream("gzip"));
	const compressed = await new Response(stream).arrayBuffer();
	const compressedReq = new Request("https://tattle.test/ingest", { method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/gzip" }, body: compressed });
	assert.equal((await worker.fetch(compressedReq, env2)).status, 413);
});

test("expected hosts alert after grace; revoked and disabled expectations stay silent", async () => {
	const env = await environment([HOST, "disabled", "fresh"]);
	for (const [host, state] of [[HOST, { at: "2020-01-01T00:00:00Z", enabled: true }], ["revoked", { at: "2020-01-01T00:00:00Z", enabled: true }], ["disabled", { at: "2020-01-01T00:00:00Z", enabled: false }], ["fresh", { at: new Date().toISOString(), enabled: true }]]) env.STATE.map.set(`expected/${host}`, JSON.stringify(state));
	const alerts = [];
	await withFetch(async (_url, opts) => { alerts.push(opts.body); return new Response("ok"); }, async () => {
		await worker.scheduled({}, env); await worker.scheduled({}, env);
		assert.equal(alerts.length, 1); assert.match(alerts[0], /laptop has never reported/);
		assert.ok((await env.STATE.get(`silence/${HOST}/${await hash(TOKEN)}`)).at);
		assert.equal((await worker.fetch(req("/ingest", report()), env)).status, 200);
		assert.equal((await env.STATE.get(`expected/${HOST}`)).enabled, true);
		await worker.scheduled({}, env);
		assert.equal(alerts.length, 1);
	});
});

test("silence isolates malformed/KV/notification failures and always pings worker-alive heartbeat", async () => {
	const env = await environment([HOST, "broken", "unavailable", "notifyfail"]);
	for (const host of [HOST, "unavailable", "notifyfail"]) await seed(env, host);
	env.STATE.map.set("seen/broken", JSON.stringify({ at: "garbage" }));
	env.STATE.failGet.add("seen/unavailable"); env.HEARTBEAT_URL = "https://heartbeat.test/alive";
	const sent = [];
	await withFetch(async (url, opts) => {
		sent.push(url === env.HEARTBEAT_URL ? "heartbeat" : opts.body);
		return new Response("ok", { status: opts?.body.includes("notifyfail") ? 500 : 200 });
	}, async () => {
		await assert.rejects(worker.scheduled({}, env), AggregateError);
		assert.ok(sent.some((s) => s.includes("laptop has not reported")));
		assert.equal(sent.at(-1), "heartbeat");
		assert.ok((await env.STATE.get(`silence/${HOST}/${await hash(TOKEN)}`)).at);
	});
});

test("canary provisioning serializes/caches one mint set per host across users and restarts", async () => {
	const env = await environment(); let mints = 0; const callbacks = [], memos = [];
	await withFetch(async (_url, opts) => {
		mints++; const data = JSON.parse(opts.body); callbacks.push(data.webhook_url); memos.push(data.memo);
		await new Promise((r) => setTimeout(r, 5));
		return Response.json(data.token_type === "dns" ? { hostname: "trip.canary.test" } : { aws_access_key_id: "AKIAKEY", aws_secret_access_key: "secret" });
	}, async () => {
		const responses = await Promise.all(["alice", "bob", "mallory"].map((user) => worker.fetch(req(`/canaries.sh?user=${user}`), env)));
		const scripts = await Promise.all(responses.map((r) => r.text()));
		assert.ok(responses.every((r) => r.status === 200)); assert.equal(new Set(scripts).size, 1); assert.equal(mints, 3);
		env.restart(); assert.equal((await worker.fetch(req("/canaries.sh?user=new"), env)).status, 200); assert.equal(mints, 3);
		assert.ok(callbacks.every((u) => !u.includes("fleet-secret") && new URL(u).searchParams.get("key").startsWith("laptop.")));
		const cached = await (await env.store()).get("canaries");
		assert.ok(["alice", "bob", "mallory"].includes(cached.user));
		assert.ok(memos.every((memo) => memo.startsWith(`tattle: laptop/${cached.user} `)));
	});
});

test("failed canary minting is host-budgeted regardless of user variation", async () => {
	const env = await environment(); let mints = 0;
	await withFetch(async () => { mints++; return Response.json({ error: true }, { status: 500 }); }, async () => {
		for (let i = 0; i < 8; i++) assert.equal((await worker.fetch(req(`/canaries.sh?user=user${i}`), env)).status, i < 6 ? 503 : 429);
		assert.equal(mints, 18);
	});
});

test("canary bodies are capped before buffering and authentication precedes reading", async () => {
	const env = await environment(); let notify = 0;
	await withFetch(async () => { notify++; return new Response("ok"); }, async () => {
		assert.equal((await worker.fetch(req("/canary?key=wrong", "x".repeat(65537)), env)).status, 401);
		assert.equal((await worker.fetch(req("/canary?key=fleet-secret", "x".repeat(65537), "fleet-secret"), env)).status, 413);
		const compressed = await new Response(new Blob(["x".repeat(65537)]).stream().pipeThrough(new CompressionStream("gzip"))).arrayBuffer();
		const input = new Request("https://tattle.test/canary?key=fleet-secret", { method: "POST", headers: { "content-encoding": "gzip" }, body: compressed });
		assert.equal((await worker.fetch(input, env)).status, 413); assert.equal(notify, 0);
	});
});

test("Unicode/CRLF notification titles stay header-safe while body retains useful text", async () => {
	const env = await environment(); const calls = [];
	await withFetch(async (_url, opts) => { calls.push(opts); new Headers(opts.headers); return new Response("ok"); }, async () => {
		const result = await worker.fetch(req("/canary", { memo: "雪 🔐\r\nInjected: title", channel: "web" }, "fleet-secret"), env);
		assert.equal(result.status, 200); assert.match(calls[0].body, /雪 🔐/);
		assert.match(calls[0].headers.Title, /^[\x20-\x7e]+$/); assert.ok(!/[\r\n]/.test(calls[0].headers.Title));
	});
});

test("corrupt operator token maps fail closed and malformed host state stays controlled", async () => {
	for (const value of [undefined, "bad", "null", "[]", '"string"', JSON.stringify({ [await hash(TOKEN)]: { host: HOST } }), JSON.stringify({ [await hash(TOKEN)]: "../bad" }), JSON.stringify({ [await hash(TOKEN)]: "Uppercase" }), JSON.stringify({ [await hash(TOKEN)]: "Constructor" }), JSON.stringify({ constructor: HOST })]) {
		const env = await environment(); env.HOST_TOKENS = value;
		assert.equal((await worker.fetch(req("/ingest", report()), env)).status, 503);
		assert.equal(env.STATE.writes + env.REPORTS.puts, 0);
	}
	const env = await environment(); env.STATE.map.set(`seen/${HOST}`, JSON.stringify({ at: {} }));
	assert.equal((await worker.fetch(req("/ingest", report()), env)).status, 503);
	const page = await (await worker.fetch(req("/hosts", undefined, "reader"), env)).json();
	assert.match(page.hosts[HOST].error, /corrupt/);
});

test("reports and hosts pagination bounds work and traverses every key including filtered empty pages", async () => {
	const env = await environment(Array.from({ length: 7 }, (_, i) => `host-${i}`));
	for (let i = 0; i < 7; i++) {
		env.STATE.map.set(`seen/host-${i}`, JSON.stringify({ at: "2020-01-01T00:00:00Z", staleAlertedAt: null }));
		env.REPORTS.map.set(`reports/host-${i}/2026-10-26T00:00:00.000Z-${i}.json`, "{}");
	}
	for (const endpoint of ["hosts", "reports"]) {
		const all = []; let cursor;
		do {
			const res = await worker.fetch(req(`/${endpoint}?pagination=1&limit=2${cursor ? `&cursor=${cursor}` : ""}`, undefined, "reader"), env);
			assert.equal(res.status, 200); const data = await res.json();
			all.push(...(endpoint === "hosts" ? Object.keys(data.hosts) : data.keys)); cursor = data.cursor;
		} while (cursor);
		assert.equal(all.length, 7); assert.equal(new Set(all).size, 7);
	}
	assert.equal(env.STATE.listCalls, 6); assert.equal(env.REPORTS.listCalls, 4);
	const filtered = await (await worker.fetch(req("/reports?pagination=1&limit=2&since=2027-01-01T00:00:00Z", undefined, "reader"), env)).json();
	assert.equal(filtered.keys.length, 0); assert.ok(filtered.cursor);
	assert.equal((await worker.fetch(req("/hosts?pagination=1&limit=501", undefined, "reader"), env)).status, 400);
	assert.equal((await worker.fetch(req("/reports?host=../bad", undefined, "reader"), env)).status, 400);
	assert.equal((await worker.fetch(req("/report?key=reports/host-0/2026-10-26T00:00:00.000Z-0.json", undefined, "reader"), env)).status, 200);
});

test("installer serves only a canonical HTTPS origin in a single-quoted assignment", async () => {
	const env = await environment();
	assert.equal(await (await worker.fetch(new Request("https://tattle.test:8443/install.sh"), env)).text(), "url='https://tattle.test:8443'\n");
	for (const url of ["http://tattle.test/install.sh", "https://bad'host.test/install.sh", "https://bad_host.test/install.sh", "https://a..b/install.sh", "https://a-.test/install.sh"]) assert.equal((await worker.fetch(new Request(url), env)).status, 400);
});


test("a later collector payload recovers durable pending work then observes the successful interval", async () => {
	const env = await environment(); await seed(env);
	let alerts = 0;
	await withFetch(async () => { alerts++; return new Response("ok", { status: alerts === 1 ? 500 : 200 }); }, async () => {
		const accepted = report({ accounts: "evil" });
		assert.equal((await worker.fetch(req("/ingest", accepted), env)).status, 503);
		const later = { ...report({ accounts: "evil\nnew-change" }), collectedAt: "2026-10-26T01:00:00Z" };
		env.restart();
		const recovered = await worker.fetch(req("/ingest", later), env);
		assert.equal(recovered.status, 429); assert.match(await recovered.text(), /previously accepted report recovered/);
		assert.equal(env.REPORTS.puts, 1); assert.equal(alerts, 2);
		const archived = JSON.parse([...env.REPORTS.map.values()][0]);
		assert.equal(archived.sections.accounts, "evil");
		assert.ok(![...(await env.store()).map.keys()].some((key) => key.startsWith("pendingBody/")));
	});
});

test("per-host HMAC canaries bind identity, reject tampering/revocation, and keep fleet key private", async () => {
	const env = await environment(); const callbacks = []; const alerts = [];
	await withFetch(async (url, opts) => {
		if (url === env.NTFY_URL) { alerts.push(opts.body); return new Response("ok"); }
		const data = JSON.parse(opts.body); callbacks.push(data.webhook_url);
		return Response.json(data.token_type === "dns" ? { hostname: "trip.canary.test" } : { aws_access_key_id: "AKIAKEY", aws_secret_access_key: "secret" });
	}, async () => {
		assert.equal((await worker.fetch(req("/canaries.sh"), env)).status, 200);
		const callback = callbacks[0];
		assert.ok(!callback.includes(env.CANARY_KEY));
		const post = (url) => new Request(url, { method: "POST", body: JSON.stringify({ memo: "other-host credential", channel: "dns" }) });
		assert.equal((await worker.fetch(post(callback), env)).status, 200);
		assert.match(alerts[0], /^laptop: CANARY TRIPPED/); assert.match(alerts[0], /Host: laptop/);
		assert.equal((await worker.fetch(post(callback.replace("laptop.", "other-host.")), env)).status, 401);
		env.HOST_TOKENS = "{}";
		assert.equal((await worker.fetch(post(callback), env)).status, 401);
		assert.equal(alerts.length, 1);
	});
});


test("hosts pagination traverses expected hosts with safe phase cursors and suppresses disabled/revoked/seen duplicates", async () => {
	const env = await environment([HOST, "never", "disabled"]);
	await seed(env);
	env.STATE.map.set(`seen/${HOST}`, JSON.stringify({ at: "2020-01-01T00:00:00Z", staleAlertedAt: null, enrollment: await hash(TOKEN) }));
	for (const [host, enabled] of [[HOST, true], ["never", true], ["disabled", false], ["revoked", true]]) env.STATE.map.set(`expected/${host}`, JSON.stringify({ at: "2026-10-26T00:00:00Z", enabled }));
	const hosts = {}; let cursor; let pages = 0;
	do {
		const res = await worker.fetch(req(`/hosts?pagination=1&limit=1${cursor ? `&cursor=${cursor}` : ""}`, undefined, "reader"), env);
		assert.equal(res.status, 200); const page = await res.json(); pages++;
		Object.assign(hosts, page.hosts); cursor = page.cursor;
	} while (cursor);
	assert.equal(pages, 6); assert.equal(env.STATE.listCalls, 6);
	assert.deepEqual(Object.keys(hosts).sort(), ["laptop", "never"]);
	assert.equal(hosts.never.status, "awaiting-first-report"); assert.equal(hosts.never.at, "2026-10-26T00:00:00Z");
	assert.equal(hosts.laptop.status, undefined);
	for (const value of ["bad", btoa(JSON.stringify({ v: 1, phase: "arbitrary", cursor: null })), btoa(JSON.stringify({ v: 1, phase: "expected", cursor: {} }))]) assert.equal((await worker.fetch(req(`/hosts?pagination=1&cursor=${encodeURIComponent(value)}`, undefined, "reader"), env)).status, 400);
});

test("notification bodies obey the provider byte limit even for multi-byte Unicode", async () => {
	const env = await environment();
	await withFetch(async (_url, opts) => {
		assert.ok(new TextEncoder().encode(opts.body).byteLength <= 3800);
		assert.ok(opts.body.includes("雪")); assert.ok(!opts.body.includes("\ufffd"));
		return new Response("ok");
	}, async () => {
		assert.equal((await worker.fetch(req("/canary", { memo: "雪".repeat(1000), additional_data: "🔥".repeat(1000) }, "fleet-secret"), env)).status, 200);
	});
});


test("removing and re-enrolling a host rejects old canaries and starts fresh admission/baseline/cache", async () => {
	const env = await environment(); const callbacks = []; const alerts = []; let mints = 0;
	await withFetch(async (url, opts) => {
		if (url === env.NTFY_URL) { alerts.push(opts.body); return new Response("ok"); }
		const data = JSON.parse(opts.body); mints++; callbacks.push(data.webhook_url);
		return Response.json(data.token_type === "dns" ? { hostname: `trip${mints}.canary.test` } : { aws_access_key_id: `AKIAKEY${mints}`, aws_secret_access_key: "secret" });
	}, async () => {
		assert.equal((await worker.fetch(req("/canaries.sh"), env)).status, 200);
		const oldCallback = callbacks[0];
		assert.equal((await worker.fetch(req("/ingest", report({ accounts: "old-user" })), env)).status, 200);
		assert.equal((await worker.fetch(req("/ingest", report({ accounts: "old-user" })), env)).status, 429);
		const oldStore = await env.store();
		assert.deepEqual(await oldStore.get("identity"), { host: HOST, tokenHash: await hash(TOKEN) });
		const oldArchive = [...env.REPORTS.map.keys()][0];
		const post = (url) => new Request(url, { method: "POST", body: JSON.stringify({ memo: "credential", channel: "dns" }) });
		env.HOST_TOKENS = "{}";
		assert.equal((await worker.fetch(post(oldCallback), env)).status, 401);
		const replacement = "new-host-secret";
		env.HOST_TOKENS = JSON.stringify({ [await hash(replacement)]: HOST });
		env.STATE.map.set(`expected/${HOST}`, JSON.stringify({ at: new Date().toISOString(), enabled: true }));
		assert.equal((await worker.fetch(post(oldCallback), env)).status, 401);
		assert.equal((await worker.fetch(req("/ingest", report()), env)).status, 401);
		assert.equal((await worker.fetch(req("/canaries.sh", undefined, replacement), env)).status, 200);
		assert.equal(mints, 6); assert.notEqual(callbacks[3], oldCallback);
		assert.equal((await worker.fetch(post(callbacks[3]), env)).status, 200);
		alerts.length = 0;
		assert.equal((await worker.fetch(req("/ingest", report({ accounts: "new-user" }), replacement), env)).status, 200);
		assert.equal(alerts.length, 0, "the new enrollment must not diff the old enrollment baseline");
		assert.equal(env.REPORTS.puts, 2); assert.ok(env.REPORTS.map.has(oldArchive));
		assert.equal(await env.store(replacement), oldStore);
		assert.equal(await oldStore.get(`retired/${await hash(TOKEN)}`), true);
		assert.equal((await env.STATE.get(`seen/${HOST}`)).enrollment, await hash(replacement));
		assert.equal((await env.STATE.get(`last/${HOST}`)).enrollment, await hash(replacement));
		assert.equal((await worker.fetch(req("/canaries.sh?user=another", undefined, replacement), env)).status, 200);
		assert.equal(mints, 6);
		assert.equal((await worker.fetch(req("/ingest", report({ accounts: "new-user" }), replacement), env)).status, 429);
	});
});

test("enabled expected enrollment bypasses untagged legacy rate/baseline while legacy migration still alerts", async () => {
	const env = await environment(); await seed(env, HOST, { accounts: "old-user" });
	env.STATE.map.set(`seen/${HOST}`, JSON.stringify({ at: new Date().toISOString(), staleAlertedAt: "2020-01-01T00:00:00Z" }));
	env.STATE.map.set(`expected/${HOST}`, JSON.stringify({ at: new Date().toISOString(), enabled: true }));
	let alerts = 0;
	await withFetch(async () => { alerts++; return new Response("ok"); }, async () => {
		assert.equal((await worker.fetch(req("/ingest", report({ accounts: "new-user" })), env)).status, 200);
		assert.equal(alerts, 0);
	});
});

test("duplicate host enrollments fail closed and vanished seen keys are omitted", async () => {
	const env = await environment();
	env.HOST_TOKENS = JSON.stringify({ [await hash(TOKEN)]: HOST, [await hash("duplicate-token")]: HOST });
	assert.equal((await worker.fetch(req("/ingest", report()), env)).status, 503);
	assert.equal((await worker.fetch(req("/canaries.sh"), env)).status, 503);
	assert.equal(env.REPORTS.puts + env.STATE.writes, 0);
	env.HOST_TOKENS = JSON.stringify({ [await hash(TOKEN)]: HOST });
	await seed(env, "revoked-legacy");
	const list = env.STATE.list.bind(env.STATE);
	env.STATE.list = async (opts) => opts.prefix === "seen/" ? { keys: [{ name: `seen/${HOST}` }, { name: "seen/revoked-legacy" }], list_complete: true } : list(opts);
	const page = await (await worker.fetch(req("/hosts", undefined, "reader"), env)).json();
	assert.deepEqual(page.hosts, {}, "vanished and revoked legacy seen hosts must both be omitted");
});


test("canary usernames reject hostile inputs before gate/provider work and preserve initial host/user memos", async () => {
	const env = await environment(); let gateLookups = 0; let providers = 0; const memos = [];
	const get = env.HOST_GATE.get.bind(env.HOST_GATE);
	env.HOST_GATE.get = (id) => { gateLookups++; return get(id); };
	await withFetch(async (_url, opts) => {
		providers++; const data = JSON.parse(opts.body); memos.push(data.memo);
		return Response.json(data.token_type === "dns" ? { hostname: "trip.canary.test" } : { aws_access_key_id: "AKIAKEY", aws_secret_access_key: "secret" });
	}, async () => {
		for (const user of ["", "-root", ".root", "alice bob", "alice/bob", "a;reboot", "$(id)", "a\nInjected", "雪", "a".repeat(129)]) {
			assert.equal((await worker.fetch(req(`/canaries.sh?user=${encodeURIComponent(user)}`), env)).status, 400, user);
		}
		assert.equal((await worker.fetch(req("/canaries.sh?user=alice&user=bob"), env)).status, 400);
		assert.equal(gateLookups, 0); assert.equal(providers, 0); assert.equal(env.stores.size, 0);
		const first = await worker.fetch(req("/canaries.sh?user=_Alice.123-test"), env);
		assert.equal(first.status, 200); const script = await first.text();
		assert.ok(memos.every((memo) => memo.startsWith("tattle: laptop/_Alice.123-test ")));
		assert.equal((await (await env.store()).get("canaries")).user, "_Alice.123-test");
		const later = await worker.fetch(req("/canaries.sh?user=other-user"), env);
		assert.equal(await later.text(), script); assert.equal(providers, 3);
		const cached = await (await env.store()).get("canaries"); cached.user = {};
		await (await env.store()).put("canaries", cached);
		assert.equal((await worker.fetch(req("/canaries.sh?user=alice"), env)).status, 503);
		assert.equal(providers, 3);
	});
});

test("a paused old ingest cannot erase the persistent marker or silence of a new enrollment", async () => {
	const env = await environment();
	const oldHash = await hash(TOKEN), newToken = "reenrolled-host-secret", newHash = await hash(newToken);
	const oldExpected = { at: "2020-01-01T00:00:00Z", enabled: true, enrollment: oldHash };
	const freshExpected = { at: "2020-02-01T00:00:00Z", enabled: true, enrollment: newHash };
	env.STATE.map.set(`expected/${HOST}`, JSON.stringify(oldExpected));
	const get = env.STATE.get.bind(env.STATE);
	let release, entered;
	const paused = new Promise((resolve) => { entered = resolve; });
	const resume = new Promise((resolve) => { release = resolve; });
	let pause = true;
	env.STATE.get = async (key) => {
		const value = await get(key);
		if (pause && key === `expected/${HOST}`) { pause = false; entered(); await resume; }
		return value;
	};
	const alerts = [];
	await withFetch(async (_url, opts) => { alerts.push(opts.body); return new Response("ok"); }, async () => {
		const oldIngest = worker.fetch(req("/ingest", report({ accounts: "old-user" })), env);
		await paused;
		env.HOST_TOKENS = JSON.stringify({ [newHash]: HOST });
		env.STATE.map.set(`expected/${HOST}`, JSON.stringify(freshExpected));
		release();
		assert.equal((await oldIngest).status, 200);
		assert.deepEqual(await get(`expected/${HOST}`), freshExpected);
		assert.equal((await get(`seen/${HOST}`)).enrollment, oldHash);
		await worker.scheduled({}, env);
		assert.equal(alerts.length, 1); assert.match(alerts[0], /laptop has never reported/);
		assert.deepEqual(await get(`expected/${HOST}`), freshExpected, "sweeps must not mutate the active enrollment marker");
		assert.ok(await get(`silence/${HOST}/${newHash}`));
		let cursor; const status = {};
		do {
			const page = await (await worker.fetch(req(`/hosts?pagination=1${cursor ? `&cursor=${cursor}` : ""}`, undefined, "reader"), env)).json();
			Object.assign(status, page.hosts); cursor = page.cursor;
		} while (cursor);
		assert.equal(status[HOST].status, "awaiting-first-report");
	});
});

test("host coordinator serializes in-flight rotations and tombstones stale enrollments permanently", async () => {
	const env = await environment(); await seed(env);
	const oldHash = await hash(TOKEN), nextToken = "next-token", nextHash = await hash(nextToken);
	let release, entered;
	const paused = new Promise((resolve) => { entered = resolve; });
	const resume = new Promise((resolve) => { release = resolve; });
	let pause = true;
	const writes = [];
	const put = env.STATE.put.bind(env.STATE);
	env.STATE.put = async (key, value) => { if (key === `seen/${HOST}`) writes.push(JSON.parse(value).enrollment); return put(key, value); };
	await withFetch(async () => {
		if (pause) { pause = false; entered(); await resume; }
		return new Response("ok");
	}, async () => {
		const oldIngest = worker.fetch(req("/ingest", report({ accounts: "old-change" })), env);
		await paused;
		env.HOST_TOKENS = JSON.stringify({ [nextHash]: HOST });
		const expected = { at: new Date().toISOString(), enabled: true, enrollment: nextHash };
		env.STATE.map.set(`expected/${HOST}`, JSON.stringify(expected));
		const nextIngest = worker.fetch(req("/ingest", report({ accounts: "new-baseline" }), nextToken), env);
		release();
		assert.equal((await oldIngest).status, 200);
		assert.equal((await nextIngest).status, 200);
		assert.deepEqual(writes, [oldHash, nextHash]);
		assert.equal((await env.STATE.get(`seen/${HOST}`)).enrollment, nextHash);
		assert.equal((await env.STATE.get(`last/${HOST}`)).enrollment, nextHash);
		assert.deepEqual(await env.STATE.get(`expected/${HOST}`), expected);
		const store = await env.store();
		assert.equal(await store.get(`retired/${oldHash}`), true);
		const currentSeen = await env.STATE.get(`seen/${HOST}`), currentLast = await env.STATE.get(`last/${HOST}`);
		// Even stale authorization configuration cannot switch the host back.
		env.HOST_TOKENS = JSON.stringify({ [oldHash]: HOST });
		assert.equal((await worker.fetch(req("/ingest", report({ accounts: "late-old" })), env)).status, 401);
		assert.deepEqual(await env.STATE.get(`seen/${HOST}`), currentSeen);
		assert.deepEqual(await env.STATE.get(`last/${HOST}`), currentLast);
		assert.deepEqual(await env.STATE.get(`expected/${HOST}`), expected);
		const thirdToken = "third-token", thirdHash = await hash(thirdToken);
		env.HOST_TOKENS = JSON.stringify({ [thirdHash]: HOST });
		env.STATE.map.set(`expected/${HOST}`, JSON.stringify({ at: new Date().toISOString(), enabled: true, enrollment: thirdHash }));
		assert.equal((await worker.fetch(req("/ingest", report({ accounts: "third-baseline" }), thirdToken), env)).status, 200);
		assert.equal(await store.get(`retired/${oldHash}`), true);
		assert.equal(await store.get(`retired/${nextHash}`), true);
		assert.equal((await store.get("identity")).tokenHash, thirdHash);
		assert.equal(env.REPORTS.puts, 3);
		await store.put(`retired/${oldHash}`, { corrupt: true });
		env.HOST_TOKENS = JSON.stringify({ [oldHash]: HOST });
		assert.equal((await worker.fetch(req("/ingest", report()), env)).status, 503);
	});
});

test("silence receipts retain recovery alerts without mutating persistent enrollment/seen records", async () => {
	const env = await environment(); await seed(env);
	const tokenHash = await hash(TOKEN);
	const seen = { at: "2020-01-01T00:00:00Z", staleAlertedAt: null, enrollment: tokenHash };
	const expected = { at: "2019-01-01T00:00:00Z", enabled: true, enrollment: tokenHash };
	env.STATE.map.set(`seen/${HOST}`, JSON.stringify(seen)); env.STATE.map.set(`expected/${HOST}`, JSON.stringify(expected));
	const alerts = [];
	await withFetch(async (_url, opts) => { alerts.push(opts.body); return new Response("ok"); }, async () => {
		await worker.scheduled({}, env); await worker.scheduled({}, env);
		assert.equal(alerts.length, 1);
		assert.deepEqual(await env.STATE.get(`seen/${HOST}`), seen);
		assert.deepEqual(await env.STATE.get(`expected/${HOST}`), expected);
		assert.equal((await worker.fetch(req("/ingest", report()), env)).status, 200);
		assert.equal(alerts.length, 2); assert.match(alerts[1], /laptop is reporting again/);
		await worker.scheduled({}, env); assert.equal(alerts.length, 2);
	});
	const corrupt = await environment();
	corrupt.STATE.map.set(`expected/${HOST}`, JSON.stringify({ at: new Date().toISOString(), enabled: true, enrollment: {} }));
	assert.equal((await worker.fetch(req("/ingest", report()), corrupt)).status, 503);
});

test("a delayed previously authorized old request cannot overwrite an already reported new enrollment", async () => {
	const env = await environment();
	const oldHash = await hash(TOKEN), nextToken = "delayed-new-token", nextHash = await hash(nextToken);
	// Establish the original active identity without consuming a report slot.
	await withFetch(async (_url, opts) => {
		const data = JSON.parse(opts.body);
		return Response.json(data.token_type === "dns" ? { hostname: "trip.canary.test" } : { aws_access_key_id: "AKIAKEY", aws_secret_access_key: "secret" });
	}, async () => { assert.equal((await worker.fetch(req("/canaries.sh?user=alice"), env)).status, 200); });
	const get = env.HOST_GATE.get.bind(env.HOST_GATE);
	let release, entered;
	const paused = new Promise((resolve) => { entered = resolve; });
	const resume = new Promise((resolve) => { release = resolve; });
	let delay = true;
	env.HOST_GATE.get = (id) => {
		const object = get(id);
		return { async fetch(request) {
			if (delay && request.headers.get("x-tattle-token-hash") === oldHash) { delay = false; entered(); await resume; }
			return object.fetch(request);
		} };
	};
	const oldIngest = worker.fetch(req("/ingest", report({ accounts: "old-delayed" })), env);
	await paused;
	env.HOST_TOKENS = JSON.stringify({ [nextHash]: HOST });
	const expected = { at: new Date().toISOString(), enabled: true, enrollment: nextHash };
	env.STATE.map.set(`expected/${HOST}`, JSON.stringify(expected));
	assert.equal((await worker.fetch(req("/ingest", report({ accounts: "new-current" }), nextToken), env)).status, 200);
	const currentSeen = await env.STATE.get(`seen/${HOST}`), currentLast = await env.STATE.get(`last/${HOST}`);
	// Simulate the delayed request reaching a gate with stale configuration.
	// Permanent DO retirement, rather than a KV/config recheck, rejects it.
	env.HOST_TOKENS = JSON.stringify({ [oldHash]: HOST });
	release();
	assert.equal((await oldIngest).status, 401);
	env.HOST_TOKENS = JSON.stringify({ [nextHash]: HOST });
	assert.deepEqual(await env.STATE.get(`seen/${HOST}`), currentSeen);
	assert.deepEqual(await env.STATE.get(`last/${HOST}`), currentLast);
	assert.deepEqual(await env.STATE.get(`expected/${HOST}`), expected);
	assert.equal(env.REPORTS.puts, 1);
});


// Exact JSON writer, section names and status consumer from the original
// collector/tattle-collect and bin/tattle at 2b8c1b8cad925855cc6ba1148f43dd5d4585f9dc.
// Embedded so release archives and shallow clones need no Git history. Only
// machine inspection is replaced; original serialization and parsing execute.
const LEGACY_FIXTURE = {
  "sections": {
    "Darwin": [
      "identity",
      "accounts",
      "ssh",
      "listening",
      "persistence",
      "posture",
      "exposure",
      "updates",
      "credentials",
      "packages",
      "tailscale"
    ],
    "Linux": [
      "identity",
      "accounts",
      "ssh",
      "listening",
      "persistence",
      "posture",
      "updates",
      "exposure",
      "credentials",
      "files",
      "containers",
      "packages",
      "tailscale",
      "lynis"
    ]
  },
  "escaping": "TAB=$(printf '\\t')\njstr() {\n\ttr -d '\\000-\\010\\013-\\037' | sed -e 's/\\\\/\\\\\\\\/g' -e 's/\"/\\\\\"/g' -e \"s/$TAB/\\\\\\\\t/g\" |\n\t\tawk '{ printf \"%s%s\", (NR > 1 ? \"\\\\n\" : \"\"), $0 }'\n}\n\n",
  "writer": "\n{\n\tprintf '{\"version\":%s,\"os\":\"%s\",\"collectedAt\":\"%s\",\"sections\":{' \\\n\t\t\"$VERSION\" \"$OS\" \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"\n\tsep=\"\"\n\tfor s in $SECTIONS; do\n\t\tprintf '%s\"%s\":\"' \"$sep\" \"$s\"\n\t\tjstr <\"$TMP/$s\"\n\t\tprintf '\"'\n\t\tsep=\",\"\n\tdone\n\tprintf '}}\\n'\n} >\"$TMP/report.json\"",
  "reader": "\nimport json, sys, datetime\nhosts = json.load(sys.stdin)[\"hosts\"]\nnow = datetime.datetime.now(datetime.timezone.utc)\nfor name, seen in sorted(hosts.items()):\n    at = datetime.datetime.fromisoformat(seen[\"at\"].replace(\"Z\", \"+00:00\"))\n    print(f\"{name:28} {int((now - at).total_seconds() // 3600):>4}h ago  {at:%Y-%m-%d %H:%M} UTC\")"
};
function originalCollectorReport(os) {
	const names = LEGACY_FIXTURE.sections[os];
	const { escaping, writer } = LEGACY_FIXTURE;
	const dir = mkdtempSync(join(tmpdir(), "tattle-original-envelope-"));
	try {
		for (const name of names) writeFileSync(join(dir, name), name === "accounts" ? 'alice "admin"\nlocal\tuser\n' : "");
		const result = spawnSync("/bin/sh", ["-c", `${escaping}\n${writer}\ncat "$TMP/report.json"`], { encoding: "utf8", env: { ...process.env, TMP: dir, OS: os, VERSION: "1", SECTIONS: names.join(" ") } });
		assert.equal(result.status, 0, result.stderr);
		const parsed = JSON.parse(result.stdout);
		assert.equal(parsed.os, os); assert.equal(parsed.version, 1); assert.equal(Object.keys(parsed.sections).length, names.length);
		return parsed;
	} finally { rmSync(dir, { recursive: true, force: true }); }
}

test("original Darwin and Linux collector envelopes preserve gzip, legacy rate limits, baseline alerts and archives", async () => {
	for (const os of ["Darwin", "Linux"]) {
		const data = originalCollectorReport(os), env = await environment();
		await seed(env, HOST, data.sections);
		const recent = { at: new Date().toISOString(), staleAlertedAt: null };
		env.STATE.map.set(`seen/${HOST}`, JSON.stringify(recent));
		let alerts = 0;
		await withFetch(async () => { alerts++; return new Response("ok"); }, async () => {
			await worker.scheduled({}, env);
			assert.equal(await env.STATE.get(`bootstrap/${HOST}/${await hash(TOKEN)}`), null);
			assert.deepEqual(await env.STATE.get(`seen/${HOST}`), recent);
			assert.deepEqual(await env.STATE.get(`last/${HOST}`), data.sections);
			assert.equal((await worker.fetch(req("/ingest", data), env)).status, 429);
			await seed(env, HOST, data.sections);
			const changed = { ...data, sections: { ...data.sections, accounts: data.sections.accounts + "\nevil" } };
			const gzip = await new Response(new Blob([JSON.stringify(changed)]).stream().pipeThrough(new CompressionStream("gzip"))).arrayBuffer();
			const response = await worker.fetch(new Request("https://tattle.test/ingest", { method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/gzip" }, body: gzip }), env);
			assert.equal(response.status, 200); assert.equal(alerts, 1);
			const archived = JSON.parse([...env.REPORTS.map.values()][0]);
			const { host, receivedAt, ...collectorPayload } = archived;
			assert.equal(host, HOST); assert.ok(Date.parse(receivedAt)); assert.deepEqual(collectorPayload, changed);
		});
	}
});

test("legacy read defaults return complete original shapes across backend pages and run the original status consumer", async () => {
	const env = await environment([HOST, "server", "never"]);
	await seed(env); await seed(env, "server");
	env.STATE.map.set(`seen/${HOST}`, JSON.stringify({ at: "2020-01-01T00:00:00Z", staleAlertedAt: null, enrollment: await hash(TOKEN) }));
	env.STATE.map.set("expected/never", JSON.stringify({ enabled: true, at: "2020-01-01T00:00:00Z" }));
	const kvList = env.STATE.list.bind(env.STATE), bucketList = env.REPORTS.list.bind(env.REPORTS);
	env.STATE.list = (opts) => kvList({ ...opts, limit: 1 });
	env.REPORTS.list = (opts) => bucketList({ ...opts, limit: 1 });
	const keys = ["2020-01-01", "2021-01-01", "2022-01-01"].map((date) => `reports/${HOST}/${date}T00:00:00.000Z-legacy.json`);
	for (const key of keys) env.REPORTS.map.set(key, JSON.stringify(originalCollectorReport("Darwin")));
	const response = await worker.fetch(req("/hosts", undefined, "reader"), env);
	assert.equal(response.status, 200); const text = await response.text(), hosts = JSON.parse(text);
	assert.deepEqual(Object.keys(hosts), ["hosts"]); assert.deepEqual(Object.keys(hosts.hosts).sort(), ["laptop", "never", "server"]);
	assert.deepEqual(hosts.hosts[HOST], { at: "2020-01-01T00:00:00Z", staleAlertedAt: null });
	const reader = LEGACY_FIXTURE.reader;
	const result = spawnSync("python3", ["-c", reader], { input: text, encoding: "utf8" });
	assert.equal(result.status, 0, result.stderr); assert.equal(result.stdout.trim().split("\n").length, 3);
	const reports = await (await worker.fetch(req("/reports", undefined, "reader"), env)).json();
	assert.deepEqual(reports, { keys });
	assert.deepEqual(await (await worker.fetch(req("/reports?host=laptop&since=2021-01-01T00:00:00.000Z", undefined, "reader"), env)).json(), { keys: keys.slice(1) });
	for (const key of reports.keys) assert.deepEqual(await (await worker.fetch(req(`/report?key=${encodeURIComponent(key)}`, undefined, "reader"), env)).json(), JSON.parse(env.REPORTS.map.get(key)));
	for (const path of ["/hosts?cursor=next", "/reports?limit=1", "/hosts?pagination=0"]) assert.equal((await worker.fetch(req(path, undefined, "reader"), env)).status, 400);
});

test("legacy resource overflow is explicit and never returns a silently partial success", async () => {
	const names = Array.from({ length: 201 }, (_, i) => `host-${i}`), env = await environment(names);
	for (const host of names) await seed(env, host);
	const hostResponse = await worker.fetch(req("/hosts", undefined, "reader"), env);
	assert.equal(hostResponse.status, 413); assert.match(await hostResponse.text(), /pagination=1/);
	assert.equal((await worker.fetch(req("/hosts?pagination=1&limit=200", undefined, "reader"), env)).status, 200);
	for (let i = 0; i < 10001; i++) env.REPORTS.map.set(`reports/laptop/2020-01-01T00:00:00.000Z-${String(i).padStart(5, "0")}.json`, "{}");
	const reportResponse = await worker.fetch(req("/reports?since=2099-01-01T00:00:00Z", undefined, "reader"), env);
	assert.equal(reportResponse.status, 413); assert.match(await reportResponse.text(), /pagination=1/);
	assert.equal((await worker.fetch(req("/reports?pagination=1", undefined, "reader"), env)).status, 200);
});

test("legacy never-reporting enrollment gains one persistent fresh grace marker then alerts and recovers", async () => {
	const env = await environment(), tokenHash = await hash(TOKEN), before = Date.now();
	const alerts = [];
	await withFetch(async (_url, opts) => { alerts.push(opts.body); return new Response("ok"); }, async () => {
		await Promise.all([worker.scheduled({}, env), worker.scheduled({}, env)]);
		const marker = await env.STATE.get(`bootstrap/${HOST}/${tokenHash}`);
		assert.equal(marker.enabled, true); assert.equal(marker.enrollment, tokenHash);
		assert.ok(Date.parse(marker.at) >= before && Date.parse(marker.at) <= Date.now());
		const writes = env.STATE.writes;
		env.restart(); await worker.scheduled({}, env); assert.equal(env.STATE.writes, writes);
		assert.deepEqual(await env.STATE.get(`bootstrap/${HOST}/${tokenHash}`), marker);
		assert.equal(await env.STATE.get(`expected/${HOST}`), null); assert.equal(alerts.length, 0);
		const hosts = await (await worker.fetch(req("/hosts", undefined, "reader"), env)).json();
		assert.deepEqual(hosts, { hosts: { [HOST]: { at: marker.at, staleAlertedAt: null, status: "awaiting-first-report" } } });
		const originalNow = Date.now;
		try { Date.now = () => Date.parse(marker.at) + 37 * 3600000; await worker.scheduled({}, env); await worker.scheduled({}, env); }
		finally { Date.now = originalNow; }
		assert.equal(alerts.length, 1); assert.match(alerts[0], /has never reported/);
		assert.deepEqual(await env.STATE.get(`bootstrap/${HOST}/${tokenHash}`), marker);
		assert.equal((await worker.fetch(req("/ingest", report()), env)).status, 200);
		const status = await (await worker.fetch(req("/hosts", undefined, "reader"), env)).json();
		assert.equal(status.hosts[HOST].status, undefined); assert.equal(Object.keys(status.hosts).length, 1);
	});
});

test("interrupted migration retains durable grace and respects explicit or tagged enrollment state", async () => {
	const env = await environment(), tokenHash = await hash(TOKEN), key = `bootstrap/${HOST}/${tokenHash}`;
	env.STATE.failPut = (k) => k === key;
	await assert.rejects(worker.scheduled({}, env), AggregateError);
	const marker = await (await env.store()).get("bootstrapExpected"); assert.ok(marker.at);
	env.restart(); env.STATE.failPut = null; await worker.scheduled({}, env);
	assert.deepEqual(await env.STATE.get(key), marker);
	for (const existing of [
		["seen", { at: "2020-01-01T00:00:00Z", staleAlertedAt: null, enrollment: await hash("previous-enrollment") }],
		["expected", { enabled: false, enrollment: tokenHash }],
		["expected", { enabled: true, at: new Date().toISOString(), enrollment: tokenHash }],
	]) {
		const other = await environment(); other.STATE.map.set(`${existing[0]}/${HOST}`, JSON.stringify(existing[1]));
		await worker.scheduled({}, other);
		assert.deepEqual(await other.STATE.get(`${existing[0]}/${HOST}`), existing[1]); assert.equal(await other.STATE.get(key), null);
	}
});

test("a paused migration cannot overwrite reenrollment, and stale retired sweeps fail closed", async () => {
	const env = await environment(), oldHash = await hash(TOKEN), nextHash = await hash("migration-replacement");
	const get = env.STATE.get.bind(env.STATE); let release, entered, pause = true;
	const paused = new Promise((resolve) => { entered = resolve; }), resume = new Promise((resolve) => { release = resolve; });
	env.STATE.get = async (key) => { const value = await get(key); if (pause && key === `bootstrap/${HOST}/${oldHash}`) { pause = false; entered(); await resume; } return value; };
	const oldSweep = worker.scheduled({}, env); await paused;
	env.HOST_TOKENS = JSON.stringify({ [nextHash]: HOST });
	const expected = { at: new Date().toISOString(), enabled: true, enrollment: nextHash };
	env.STATE.map.set(`expected/${HOST}`, JSON.stringify(expected)); release(); await oldSweep;
	assert.deepEqual(await get(`expected/${HOST}`), expected);
	await worker.scheduled({}, env);
	assert.deepEqual(await get(`expected/${HOST}`), expected);
	assert.equal(await (await env.store()).get(`retired/${oldHash}`), true);
	const hosts = await (await worker.fetch(req("/hosts", undefined, "reader"), env)).json();
	assert.deepEqual(hosts.hosts[HOST], { at: expected.at, staleAlertedAt: null, status: "awaiting-first-report" });
	env.HOST_TOKENS = JSON.stringify({ [oldHash]: HOST });
	await assert.rejects(worker.scheduled({}, env), AggregateError);
	assert.deepEqual(await get(`expected/${HOST}`), expected);
});

test("reenrollment without an explicit marker never accepts an untagged legacy baseline or rate state", async () => {
	const env = await environment(); await seed(env);
	await withFetch(async () => new Response("ok"), async () => { await worker.scheduled({}, env); });
	const token = "replacement-without-marker", nextHash = await hash(token);
	env.HOST_TOKENS = JSON.stringify({ [nextHash]: HOST });
	env.STATE.map.set(`seen/${HOST}`, JSON.stringify({ at: new Date().toISOString(), staleAlertedAt: "2020-01-01T00:00:00Z" }));
	let alerts = 0;
	await withFetch(async () => { alerts++; return new Response("ok"); }, async () => {
		assert.equal((await worker.fetch(req("/ingest", report({ accounts: "new-user" }), token), env)).status, 200);
		assert.equal(alerts, 0);
	});
});

test("bounded fleet sweeps persist progress past failures and cover config additions before the cursor", async () => {
	const names = Array.from({ length: 501 }, (_, i) => `host-${String(i).padStart(3, "0")}`), env = await environment(names);
	env.STATE.failGet.add(`seen/${names[0]}`); await seed(env, names[1]);
	let notifications = 0;
	await withFetch(async () => { notifications++; return new Response("ok"); }, async () => {
		await assert.rejects(worker.scheduled({}, env), AggregateError);
		assert.equal(env.stores.size, 500); assert.equal(notifications, 1);
		const progress = await env.STATE.get("sweep/host-cursor"); assert.equal(progress.v, 1); assert.equal(progress.after, names[499]);
		assert.equal(await env.STATE.get(`bootstrap/${names[500]}/${await hash("token-500")}`), null);
		env.restart(); await worker.scheduled({}, env);
		assert.ok(await env.STATE.get(`bootstrap/${names[500]}/${await hash("token-500")}`));
		const config = JSON.parse(env.HOST_TOKENS), added = "a-new-host", addedHash = await hash("new-before-cursor");
		config[addedHash] = added; env.HOST_TOKENS = JSON.stringify(config); env.STATE.failGet.clear();
		await worker.scheduled({}, env);
		assert.ok(await env.STATE.get(`bootstrap/${added}/${addedHash}`));
		assert.notEqual((await env.STATE.get("sweep/host-cursor")).config, progress.config);
	});
});


test("legacy listings stop at bounded page counts even when backend pages contain no keys", async () => {
	const env = await environment(); let kvPages = 0, reportPages = 0;
	env.STATE.list = async () => ({ keys: [], list_complete: false, cursor: String(++kvPages) });
	env.REPORTS.list = async () => ({ objects: [], truncated: true, cursor: String(++reportPages) });
	assert.equal((await worker.fetch(req("/hosts", undefined, "reader"), env)).status, 413);
	assert.equal((await worker.fetch(req("/reports", undefined, "reader"), env)).status, 413);
	assert.equal(kvPages, 100); assert.equal(reportPages, 100);
});
