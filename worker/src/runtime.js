// Runtime logic is separate from the text-asset entry point so it can be tested
// offline with the same Web APIs used by Workers.
import { diffSections } from "./diff.js";
import { mintCanaries, plantScript } from "./canaries.js";

const MAX_BODY = 2 * 1024 * 1024;
const MAX_CANARY_BODY = 64 * 1024;
const HOUR = 3600000;
const DAY = 24 * HOUR;
const LEASE = 2 * 60 * 1000;
const MAX_ATTEMPTS = 6;
const LEGACY_HOST_SCAN_LIMIT = 200;
const LEGACY_REPORT_SCAN_LIMIT = 10000;
const LEGACY_LIST_PAGE_LIMIT = 100;
const LEGACY_RESPONSE_BYTES = 4 * 1024 * 1024;
const SWEEP_BATCH = 500;
const encoder = new TextEncoder();
const badKeys = new Set(["__proto__", "constructor", "prototype"]);
const plain = (v) => v !== null && typeof v === "object" && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const hostName = (v) => typeof v === "string" && /^[a-z0-9][a-z0-9._-]{0,127}$/.test(v) && !badKeys.has(v);
const canaryUser = (v) => typeof v === "string" && /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(v);
const stamp = (v) => typeof v === "string" && v.length <= 40 && /^\d{4}-\d\d-\d\dT/.test(v) && Number.isFinite(Date.parse(v));
const reply = (body, status = 200, headers = {}) => new Response(body, { status, headers });
const text = (body) => reply(body, 200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
class HttpError extends Error {
	constructor(status, message) { super(message); this.status = status; }
}

export function createWorker({ collectorScript = "", installScript = "" } = {}) {
	return {
		async fetch(request, env) {
			try {
				const url = new URL(request.url);
				if (request.method === "POST" && url.pathname === "/ingest") {
					const enrollment = await hostForToken(request, env);
					if (!enrollment) return reply("unauthorized\n", 401);
					const report = await readReport(request);
					return await gate(env, enrollment).fetch(new Request("https://host-gate/ingest", {
						method: "POST", headers: { "x-tattle-host": enrollment.host, "x-tattle-token-hash": enrollment.tokenHash, "content-type": "application/json" }, body: JSON.stringify(report),
					}));
				}
				if (request.method === "POST" && url.pathname === "/canary") return await canary(request, env, url);
				if (request.method === "GET" && url.pathname === "/reports") return await listReports(request, env, url);
				if (request.method === "GET" && url.pathname === "/report") return await getReport(request, env, url);
				if (request.method === "GET" && url.pathname === "/hosts") return await listHosts(request, env, url);
				if (request.method === "GET" && url.pathname === "/canaries.sh") {
					const enrollment = await hostForToken(request, env);
					if (!enrollment) return reply("unauthorized\n", 401);
					const users = url.searchParams.getAll("user");
					const user = users.length ? users[0] : "user";
					if (users.length > 1 || !canaryUser(user)) throw new HttpError(400, "invalid canary user (1-128 ASCII letters, digits, underscore, dot or hyphen; start with a letter, digit or underscore)");
					return await gate(env, enrollment).fetch(new Request("https://host-gate/canaries.sh", {
						headers: { "x-tattle-host": enrollment.host, "x-tattle-token-hash": enrollment.tokenHash, "x-tattle-user": user, "x-tattle-origin": validOrigin(url.origin) },
					}));
				}
				if (request.method === "GET" && url.pathname === "/tattle-collect") return text(collectorScript);
				if (request.method === "GET" && url.pathname === "/install.sh") {
					// The installer places this substitution inside single quotes.
					return text(installScript.replace("__TATTLE_URL__", shellSingleQuoteContent(validOrigin(url.origin))));
				}
				return reply("not found\n", 404);
			} catch (err) { return errorResponse(err); }
		},
		async scheduled(_event, env) {
			let failure;
			try { await checkSilence(env); } catch (err) { failure = err; }
			// Heartbeat means the Worker ran, even if a dependency/host failed.
			// Reject the scheduled invocation afterwards so sweep errors stay visible.
			try {
				if (env.HEARTBEAT_URL) {
					const res = await fetch(env.HEARTBEAT_URL);
					if (!res.ok) throw new Error(`heartbeat failed: ${res.status}`);
				}
			} catch (err) { console.error("heartbeat failed", err); failure ||= err; }
			if (failure) throw failure;
		},
	};
}

function gate(env, { host, tokenHash }) {
	if (!env.HOST_GATE || typeof env.HOST_GATE.idFromName !== "function" || typeof env.HOST_GATE.get !== "function") {
		throw new HttpError(503, "HOST_GATE Durable Object binding is required; configure its binding and migration before ingest/provisioning");
	}
	return env.HOST_GATE.get(env.HOST_GATE.idFromName(host));
}

// One host Durable Object coordinates every enrollment, including rotations.
// Permanent per-hash tombstones prevent delayed requests reactivating old state.
// The queue also serializes across await points; KV is only a query/sweep view.
export class HostGate {
	constructor(state, env) { this.state = state; this.env = env; this.queue = Promise.resolve(); }
	fetch(request) {
		const work = this.queue.then(() => this.handle(request));
		this.queue = work.catch(() => {});
		return work.catch(errorResponse);
	}
	async handle(request) {
		const host = request.headers.get("x-tattle-host");
		const tokenHash = request.headers.get("x-tattle-token-hash");
		if (!hostName(host) || !/^[a-f0-9]{64}$/.test(tokenHash || "")) throw new HttpError(400, "bad host enrollment");
		if (tokenConfig(this.env)[tokenHash] !== host) throw new HttpError(401, "host enrollment is no longer active");
		const identity = await this.state.storage.get("identity");
		if (identity !== undefined && (!plain(identity) || identity.host !== host || typeof identity.tokenHash !== "string" || !/^[a-f0-9]{64}$/.test(identity.tokenHash))) throw new HttpError(503, "host gate identity mismatch");
		const retired = await this.state.storage.get(`retired/${tokenHash}`);
		if (retired !== undefined && retired !== true) throw new HttpError(503, "corrupt retired enrollment state");
		if (retired === true) throw new HttpError(401, "host enrollment has been retired");
		const path = new URL(request.url).pathname;
		if (path === "/sweep" && request.method === "POST") {
			await this.activate(host, tokenHash, identity);
			await this.initializeExpected(host, tokenHash);
			await checkHostSilence(this.env, host, tokenHash, await this.allowLegacy());
			return reply("ok\n");
		}
		if (path === "/ingest" && request.method === "POST") {
			// No writes, even to DO storage, until the entire report is valid.
			const report = await readReport(request);
			await this.activate(host, tokenHash, identity);
			return this.ingest(host, tokenHash, report);
		}
		if (path === "/canaries.sh") {
			const origin = validOrigin(request.headers.get("x-tattle-origin"));
			const user = request.headers.get("x-tattle-user");
			if (!canaryUser(user)) throw new HttpError(400, "invalid canary user");
			await this.activate(host, tokenHash, identity);
			return this.provision(host, tokenHash, origin, user);
		}
		return reply("not found\n", 404);
	}
	async activate(host, tokenHash, identity) {
		if (identity?.tokenHash === tokenHash) return;
		// The host queue serializes all work across enrollments. Switching the
		// active hash retires the previous one and resets only local state;
		// immutable report archives and enrollment tombstones remain intact.
		await this.state.storage.transaction(async (storage) => {
			if (identity) await storage.put(`retired/${identity.tokenHash}`, true);
			for (const key of ["reportState", "reportAttempts", "canaries", "canaryAttempts", "bootstrapExpected"]) await storage.delete(key);
			for (let i = 0; i < 32; i++) await storage.delete(`pendingBody/${i}`);
			await storage.put("legacyAllowed", !identity);
			await storage.put("identity", { host, tokenHash });
		});
	}
	async allowLegacy() {
		const allowed = await this.state.storage.get("legacyAllowed");
		if (allowed !== undefined && typeof allowed !== "boolean") throw new HttpError(503, "corrupt legacy migration state");
		return allowed !== false;
	}

	async initializeExpected(host, tokenHash) {
		// Shared markers belong to the enrollment tool. Never rewrite them or a
		// reporting host's legacy state, including disabled/corrupt records.
		if (await this.env.STATE.get(`expected/${host}`, "json") !== null || await this.env.STATE.get(`seen/${host}`, "json") !== null) return;
		let marker = await this.state.storage.get("bootstrapExpected");
		if (marker !== undefined && (!plain(marker) || marker.enrollment !== tokenHash || marker.enabled !== true || !stamp(marker.at))) throw new HttpError(503, "corrupt bootstrap enrollment state");
		if (!marker) {
			marker = { at: new Date().toISOString(), enabled: true, enrollment: tokenHash };
			// Commit grace before the KV write: interruption or concurrent sweeps
			// retry the original timestamp rather than extending enrollment grace.
			await this.state.storage.put("bootstrapExpected", marker);
		}
		const key = `bootstrap/${host}/${tokenHash}`;
		const existing = await this.env.STATE.get(key, "json");
		if (existing !== null) {
			if (!plain(existing) || existing.enrollment !== tokenHash || existing.enabled !== true || !stamp(existing.at)) throw new HttpError(503, "corrupt bootstrap enrollment marker");
			return;
		}
		// A stale initializer can only write its own immutable enrollment key.
		// Explicit shared markers always take precedence, even if written while
		// this call was paused. The host DO serializes initialization and ingest.
		await this.env.STATE.put(key, JSON.stringify(marker));
	}

	async attempt(kind, now) {
		const key = `${kind}Attempts`;
		let budget = await this.state.storage.get(key);
		if (budget !== undefined && (!plain(budget) || !Number.isFinite(budget.start) || !Number.isInteger(budget.count) || budget.count < 0)) throw new HttpError(503, "corrupt host admission state");
		if (!budget || now - budget.start >= HOUR) budget = { start: now, count: 0 };
		if (budget.count >= MAX_ATTEMPTS) throw new HttpError(429, "host retry budget exhausted; retry after one hour");
		await this.state.storage.put(key, { ...budget, count: budget.count + 1 });
	}
	async ingest(host, tokenHash, report) {
		const env = this.env;
		const now = Date.now();
		let current = await this.state.storage.get("reportState");
		if (current !== undefined && !validReportState(current, host)) throw new HttpError(503, "corrupt durable report state");
		const expected = await readExpected(env, host, tokenHash);
		const allowLegacy = !expected && await this.allowLegacy();
		const seen = await readSeen(env, host, tokenHash, allowLegacy);
		const successfulAt = current?.successfulAt || (!current?.pending && seen?.at);
		if (successfulAt && now - Date.parse(successfulAt) < HOUR) return reply("too soon\n", 429, { "Retry-After": String(Math.ceil((HOUR - (now - Date.parse(successfulAt))) / 1000)) });
		const fingerprint = await sha256(JSON.stringify(report));
		let pending = current?.pending;
		const differentReport = pending && pending.fingerprint !== fingerprint;
		if (pending?.leaseUntil > now) return reply("accepted report is recovering; retry shortly\n", 503, { "Retry-After": "120" });
		await this.attempt("report", now);
		if (!pending) {
			const receivedAt = new Date(now).toISOString();
			pending = { fingerprint, key: `reports/${host}/${receivedAt}-${crypto.randomUUID()}.json`, receivedAt, archived: false, notifications: null, nextNotification: 0, leaseUntil: now + LEASE };
			const payload = encoder.encode(JSON.stringify(report));
			pending.chunks = Math.ceil(payload.byteLength / 65536);
			current = { ...(current || {}), pending };
			// Atomic payload + admission record: a crash cannot strand an archive
			// receipt whose original collector payload has already disappeared.
			await this.state.storage.transaction(async (storage) => {
				for (let i = 0; i < pending.chunks; i++) await storage.put(`pendingBody/${i}`, payload.slice(i * 65536, (i + 1) * 65536));
				await storage.put("reportState", current);
			});
		} else {
			report = await this.pendingReport(pending);
			pending.leaseUntil = now + LEASE;
			await this.state.storage.put("reportState", current);
		}
		try {
			// Never delete/overwrite reports: the bucket may enforce retention lock.
			// The stable key and atomic create recover a crash after R2 accepted it.
			if (!pending.archived) {
				const exists = await env.REPORTS.head(pending.key);
				if (!exists) {
					const result = await env.REPORTS.put(pending.key, JSON.stringify({ ...report, host, receivedAt: pending.receivedAt }), {
						httpMetadata: { contentType: "application/json" }, onlyIf: { etagDoesNotMatch: "*" },
					});
					if (result === null && !(await env.REPORTS.head(pending.key))) throw new Error("archive conditional create failed");
				}
				pending.archived = true;
				await this.state.storage.put("reportState", current);
			}
			if (!pending.notifications) {
				const previous = await previousSections(env, host, current.lastReportKey, tokenHash, allowLegacy);
				const findings = previous ? diffSections(previous, report.sections) : [];
				pending.notifications = [];
				if (findings.length) pending.notifications.push({ title: `${host}: ${findings.length} security-relevant change${findings.length > 1 ? "s" : ""}`, message: findings.slice(0, 20).join("\n").slice(0, 3800), priority: 4, tags: "warning" });
				if (seen?.staleAlertedAt) pending.notifications.push({ title: `${host} is reporting again`, message: "It had gone quiet.", priority: 3, tags: "white_check_mark" });
				await this.state.storage.put("reportState", current);
			}
			while (pending.nextNotification < pending.notifications.length) {
				const alert = pending.notifications[pending.nextNotification];
				await notify(env, alert.title, alert.message, alert);
				pending.nextNotification++;
				await this.state.storage.put("reportState", current);
			}
			// Persist the complete view before acknowledging admission. A KV failure
			// retries these writes using the same archive and notification receipts.
			await env.STATE.put(`last/${host}`, JSON.stringify({ reportKey: pending.key, enrollment: tokenHash }));
			await env.STATE.put(`seen/${host}`, JSON.stringify({ at: pending.receivedAt, staleAlertedAt: null, enrollment: tokenHash }));
			await this.state.storage.transaction(async (storage) => {
				await storage.put("reportState", { successfulAt: new Date(Date.now()).toISOString(), lastReportKey: pending.key });
				for (let i = 0; i < pending.chunks; i++) await storage.delete(`pendingBody/${i}`);
			});
			return differentReport ? reply("previously accepted report recovered; retry the current report after one hour\n", 429, { "Retry-After": "3600", "X-Tattle-Report-Key": pending.key }) : reply("ok\n", 200, { "X-Tattle-Report-Key": pending.key });
		} catch (err) {
			pending.leaseUntil = 0;
			await this.state.storage.put("reportState", current);
			throw err;
		}
	}
	async pendingReport(pending) {
		const chunks = [];
		for (let i = 0; i < pending.chunks; i++) {
			const chunk = await this.state.storage.get(`pendingBody/${i}`);
			if (!(chunk instanceof Uint8Array) || chunk.byteLength > 65536) throw new HttpError(503, "corrupt pending report payload");
			chunks.push(chunk);
		}
		const payload = await new Blob(chunks).text();
		if (await sha256(payload) !== pending.fingerprint) throw new HttpError(503, "corrupt pending report fingerprint");
		const report = JSON.parse(payload);
		if (!validReport(report)) throw new HttpError(503, "corrupt pending report schema");
		return report;
	}
	async provision(host, tokenHash, origin, user) {
		let state = await this.state.storage.get("canaries");
		if (state !== undefined && (!plain(state) || !canaryUser(state.user) || (state.script !== undefined && (typeof state.script !== "string" || state.script.length > 32768)) || !Number.isFinite(state.leaseUntil))) throw new HttpError(503, "corrupt canary provisioning state");
		if (state?.script) return text(state.script);
		const now = Date.now();
		if (state?.leaseUntil > now) return reply("canary provisioning is recovering; retry shortly\n", 503, { "Retry-After": "120" });
		if (typeof this.env.CANARY_KEY !== "string" || !this.env.CANARY_KEY) throw new HttpError(503, "CANARY_KEY must be configured before provisioning");
		await this.attempt("canary", now);
		state = { user, leaseUntil: now + LEASE };
		await this.state.storage.put("canaries", state);
		try {
			const callback = `${host}.${await canaryMac(this.env.CANARY_KEY, host, tokenHash)}`;
			const script = plantScript(await mintCanaries(this.env, origin, `${host}/${user}`, callback));
			await this.state.storage.put("canaries", { user, script, leaseUntil: 0 });
			return text(script);
		} catch (err) {
			await this.state.storage.put("canaries", { user, leaseUntil: 0 });
			throw err;
		}
	}
}

function validReportState(value, host) {
	if (!plain(value) || (value.successfulAt !== undefined && !stamp(value.successfulAt)) || (value.lastReportKey !== undefined && !reportKey(value.lastReportKey, host))) return false;
	const p = value.pending;
	if (p === undefined) return true;
	return plain(p) && Number.isInteger(p.chunks) && p.chunks > 0 && p.chunks <= 32 && /^[0-9a-f]{64}$/.test(p.fingerprint) && reportKey(p.key, host) && stamp(p.receivedAt) && typeof p.archived === "boolean" && Number.isFinite(p.leaseUntil) && Number.isInteger(p.nextNotification) && p.nextNotification >= 0 && ((p.notifications === null && p.nextNotification === 0) || (Array.isArray(p.notifications) && p.notifications.length <= 2 && p.nextNotification <= p.notifications.length && p.notifications.every((a) => plain(a) && typeof a.title === "string" && a.title.length <= 300 && typeof a.message === "string" && a.message.length <= 3800 && Number.isInteger(a.priority) && typeof a.tags === "string")));
}
const reportKey = (key, host) => typeof key === "string" && key.startsWith(`reports/${host}/`) && key.length < 400 && !/[\r\n]/.test(key);

function validSections(sections) {
	if (!plain(sections)) return false;
	const entries = Object.entries(sections);
	return entries.length > 0 && entries.length <= 64 && entries.every(([name, value]) => /^[a-z][a-z0-9_]{0,63}$/.test(name) && !badKeys.has(name) && typeof value === "string" && encoder.encode(value).byteLength <= MAX_BODY);
}
function validReport(report) {
	if (!plain(report) || !validSections(report.sections)) return false;
	const allowed = new Set(["version", "os", "collectedAt", "sections", "host", "receivedAt"]);
	if (!Object.keys(report).every((key) => allowed.has(key))) return false;
	return Number.isInteger(report.version) && report.version > 0 && report.version <= 10000 && typeof report.os === "string" && /^[a-zA-Z0-9._-]{1,64}$/.test(report.os) && stamp(report.collectedAt) && (report.host === undefined || hostName(report.host)) && (report.receivedAt === undefined || stamp(report.receivedAt));
}
async function readReport(request) {
	let report;
	try { report = JSON.parse(await readBounded(request, MAX_BODY)); } catch (err) {
		if (err instanceof HttpError) throw err;
		throw new HttpError(400, "bad report");
	}
	if (!validReport(report)) throw new HttpError(400, "bad report schema");
	// Server fields cannot influence deduplication or the archived identity.
	const { host: _host, receivedAt: _receivedAt, ...payload } = report;
	return payload;
}
async function readBounded(request, limit) {
	if (!request.body) throw new HttpError(400, "missing body");
	let stream = request.body;
	const encoding = request.headers.get("content-encoding") || "";
	const type = request.headers.get("content-type") || "";
	if (encoding && encoding !== "identity" && encoding !== "gzip") throw new HttpError(400, "unsupported content encoding");
	try {
		if (encoding === "gzip" || type.includes("gzip")) stream = stream.pipeThrough(new DecompressionStream("gzip"));
		let size = 0;
		stream = stream.pipeThrough(new TransformStream({ transform(chunk, controller) {
			size += chunk.byteLength;
			if (size > limit) controller.error(new HttpError(413, "body too large")); else controller.enqueue(chunk);
		} }));
		return await new Response(stream).text();
	} catch (err) {
		if (err instanceof HttpError) throw err;
		throw new HttpError(400, "invalid body encoding");
	}
}

async function readSeen(env, host, tokenHash, allowLegacy = true) {
	const seen = await env.STATE.get(`seen/${host}`, "json");
	if (seen === null) return null;
	if (tokenHash !== undefined) {
		if (plain(seen) && seen.enrollment !== undefined) {
			if (typeof seen.enrollment !== "string" || !/^[a-f0-9]{64}$/.test(seen.enrollment)) throw new HttpError(503, `corrupt seen enrollment for ${host}`);
			if (seen.enrollment !== tokenHash) return null;
		} else if (!allowLegacy) return null;
	}
	if (!plain(seen) || !stamp(seen.at) || (seen.enrollment !== undefined && !/^[a-f0-9]{64}$/.test(seen.enrollment)) || (seen.staleAlertedAt !== null && seen.staleAlertedAt !== undefined && !stamp(seen.staleAlertedAt))) throw new HttpError(503, `corrupt seen state for ${host}`);
	const receipt = tokenHash === undefined ? null : await readSilenceReceipt(env, host, tokenHash);
	return receipt?.kind === "seen" && receipt.baselineAt === seen.at ? { ...seen, staleAlertedAt: receipt.at } : seen;
}
async function readExpected(env, host, tokenHash, source = "any") {
	let value = await env.STATE.get(`expected/${host}`, "json");
	if ((source === "bootstrap" && value !== null) || (source === "shared" && value === null)) return null;
	if (value === null && tokenHash !== undefined) value = await env.STATE.get(`bootstrap/${host}/${tokenHash}`, "json");
	if (value === null) return null;
	if (!plain(value)) throw new HttpError(503, `corrupt expected state for ${host}`);
	if (value.enrollment !== undefined && (typeof value.enrollment !== "string" || !/^[a-f0-9]{64}$/.test(value.enrollment))) throw new HttpError(503, `corrupt expected enrollment for ${host}`);
	if (value.enabled === false) return null;
	if (tokenHash !== undefined && value.enrollment !== undefined && value.enrollment !== tokenHash) return null;
	const at = value.at || value.enrolledAt || value.createdAt;
	if (value.enabled !== true || !stamp(at) || (value.staleAlertedAt !== undefined && value.staleAlertedAt !== null && !stamp(value.staleAlertedAt))) throw new HttpError(503, `corrupt expected state for ${host}`);
	return { ...value, at };
}
async function readSilenceReceipt(env, host, tokenHash) {
	const receipt = await env.STATE.get(`silence/${host}/${tokenHash}`, "json");
	if (receipt === null) return null;
	if (!plain(receipt) || !["seen", "expected"].includes(receipt.kind) || !stamp(receipt.at) || !stamp(receipt.baselineAt)) throw new HttpError(503, `corrupt silence receipt for ${host}`);
	return receipt;
}
function enrollmentSeen(seen, tokenHash, allowLegacy) {
	return seen && (seen.enrollment ? seen.enrollment === tokenHash : allowLegacy) ? seen : null;
}
async function previousSections(env, host, key, tokenHash, allowLegacy) {
	let value;
	if (!key) {
		value = await env.STATE.get(`last/${host}`, "json");
		if (value === null || (!allowLegacy && (!plain(value) || !Object.hasOwn(value, "reportKey") || !Object.hasOwn(value, "enrollment")))) return null;
		if (plain(value) && Object.keys(value).every((k) => ["reportKey", "enrollment"].includes(k)) && reportKey(value.reportKey, host)) {
			if (value.enrollment !== undefined && !/^[a-f0-9]{64}$/.test(value.enrollment)) throw new HttpError(503, `corrupt baseline enrollment for ${host}`);
			if (value.enrollment ? value.enrollment !== tokenHash : !allowLegacy) return null;
			key = value.reportKey;
		} else if (validSections(value)) return allowLegacy ? value : null;
		else throw new HttpError(503, `corrupt baseline for ${host}`);
	}
	const archive = await env.REPORTS.get(key);
	if (!archive) throw new HttpError(503, `missing baseline archive for ${host}`);
	const report = await archive.json();
	if (!validReport(report) || report.host !== host) throw new HttpError(503, `corrupt baseline archive for ${host}`);
	return report.sections;
}

async function checkHostSilence(env, host, tokenHash, allowLegacy) {
	const hours = Number(env.STALE_HOURS || 36);
	if (!Number.isFinite(hours) || hours <= 0 || hours > 8760) throw new Error("invalid STALE_HOURS");
	const expected = await readExpected(env, host, tokenHash);
	const seen = enrollmentSeen(await readSeen(env, host, tokenHash, !expected && allowLegacy), tokenHash, !expected && allowLegacy);
	if (!seen && !expected) return;
	const now = Date.now(), at = seen?.at || expected.at;
	const receipt = seen ? null : await readSilenceReceipt(env, host, tokenHash);
	const staleAlertedAt = seen ? seen.staleAlertedAt : receipt?.kind === "expected" && receipt.baselineAt === expected.at ? receipt.at : expected.staleAlertedAt;
	const quietFor = now - Date.parse(at);
	if (quietFor < hours * HOUR || (staleAlertedAt && now - Date.parse(staleAlertedAt) < DAY)) return;
	await notify(env, seen ? `${host} has not reported for ${Math.round(quietFor / HOUR)}h` : `${host} has never reported`, seen ? `Last report ${at}. Check the machine is up and the collector still runs.` : `Enrolled ${at}; no report arrived within the ${hours}h grace period. Check enrollment and the collector.`, { priority: 4, tags: "mute" });
	await env.STATE.put(`silence/${host}/${tokenHash}`, JSON.stringify({ kind: seen ? "seen" : "expected", baselineAt: at, at: new Date(now).toISOString() }));
}
async function checkSilence(env) {
	const enrolled = Object.entries(tokenConfig(env)).sort((a, b) => a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0);
	const hours = Number(env.STALE_HOURS || 36);
	if (!Number.isFinite(hours) || hours <= 0 || hours > 8760) throw new Error("invalid STALE_HOURS");
	const cursor = await env.STATE.get("sweep/host-cursor", "json");
	if (cursor !== null && (!plain(cursor) || cursor.v !== 1 || !hostName(cursor.after) || !/^[a-f0-9]{64}$/.test(cursor.config || ""))) throw new Error("corrupt silence sweep cursor");
	const config = await sha256(JSON.stringify(enrolled));
	let start = cursor === null || cursor.config !== config ? 0 : enrolled.findIndex(([, host]) => host > cursor.after);
	if (start < 0) start = 0;
	const batch = enrolled.slice(start, start + SWEEP_BATCH);
	const failures = [];
	for (const [tokenHash, host] of batch) {
		try {
			const response = await gate(env, { host, tokenHash }).fetch(new Request("https://host-gate/sweep", {
				method: "POST", headers: { "x-tattle-host": host, "x-tattle-token-hash": tokenHash },
			}));
			if (!response.ok) throw new Error(`silence check failed for ${host}: ${response.status} ${await response.text()}`);
		} catch (err) { console.error(`silence check failed for ${host}`, err); failures.push(err); }
	}
	// Advance even after individual host failures so a corrupt host cannot
	// starve the fleet; it is retried on the next bounded traversal.
	if (enrolled.length > SWEEP_BATCH) await env.STATE.put("sweep/host-cursor", JSON.stringify({ v: 1, after: batch.at(-1)[1], config }));
	if (failures.length) throw new AggregateError(failures, `${failures.length} silence sweep operation(s) failed`);
}

async function canary(request, env, url) {
	const supplied = bearer(request) || url.searchParams.get("key") || "";
	if (typeof env.CANARY_KEY !== "string" || !env.CANARY_KEY) return reply("unauthorized\n", 401);
	let host = null;
	if (!timingSafeEqual(supplied, env.CANARY_KEY)) {
		const split = supplied.lastIndexOf(".");
		host = supplied.slice(0, split);
		if (split < 1 || !hostName(host)) return reply("unauthorized\n", 401);
		const active = Object.entries(tokenConfig(env)).find(([, name]) => name === host);
		if (!active || !timingSafeEqual(supplied.slice(split + 1), await canaryMac(env.CANARY_KEY, host, active[0]))) return reply("unauthorized\n", 401);
	}
	// Authentication precedes even opening/decompressing the body.
	const raw = await readBounded(request, MAX_CANARY_BODY);
	let memo = "", detail = raw.slice(0, 1500);
	try {
		const hit = JSON.parse(raw);
		if (plain(hit)) {
			memo = typeof hit.memo === "string" ? hit.memo.slice(0, 1000) : "";
			detail = [typeof hit.channel === "string" && hit.channel.slice(0, 200), typeof hit.src_ip === "string" && `from ${hit.src_ip.slice(0, 200)}`, typeof hit.time === "string" && hit.time.slice(0, 100), hit.additional_data && JSON.stringify(hit.additional_data).slice(0, 800)].filter(Boolean).join("\n");
		}
	} catch { /* Providers may send form-encoded bodies. */ }
	if (/newly saved webhook works/i.test(memo)) return reply("ok\n");
	await notify(env, `${host ? `${host}: ` : ""}CANARY TRIPPED ${memo}`.trim(), `${host ? `Host: ${host}\n` : ""}${detail || "A canary token was used."}`, { priority: 5, tags: "rotating_light" });
	return reply("ok\n");
}

function pageOptions(url, maxCursor = 4096) {
	const raw = url.searchParams.get("limit") || "100";
	if (!/^\d{1,3}$/.test(raw) || Number(raw) < 1 || Number(raw) > 500) throw new HttpError(400, "limit must be between 1 and 500");
	const cursor = url.searchParams.get("cursor") || undefined;
	if (cursor && (cursor.length > maxCursor || /[\x00-\x20\x7f]/.test(cursor))) throw new HttpError(400, "bad cursor");
	return { limit: Number(raw), cursor };
}
function paginated(url) {
	const mode = url.searchParams.get("pagination");
	if (mode !== null && mode !== "1") throw new HttpError(400, "pagination must be 1 when supplied");
	if (mode === null && (url.searchParams.has("cursor") || url.searchParams.has("limit"))) throw new HttpError(400, "cursor and limit require pagination=1");
	return mode === "1";
}
function legacyOverflow(kind) { return new HttpError(413, `complete ${kind} response exceeds legacy resource limit; retry with pagination=1`); }
function legacyJson(body, kind) {
	const serialized = JSON.stringify(body);
	if (encoder.encode(serialized).byteLength > LEGACY_RESPONSE_BYTES) throw legacyOverflow(kind);
	return reply(serialized, 200, { "content-type": "application/json" });
}
async function listReports(request, env, url) {
	if (!authorizedReader(request, env)) return reply("unauthorized\n", 401);
	const host = url.searchParams.get("host");
	if (host !== null && !hostName(host)) throw new HttpError(400, "bad host");
	const since = url.searchParams.get("since") || "";
	if (since && !stamp(since)) throw new HttpError(400, "bad since");
	const prefix = host ? `reports/${host}/` : "reports/";
	const include = (obj) => !since || obj.key.split("/").pop() >= since;
	if (paginated(url)) {
		const options = pageOptions(url);
		const page = await env.REPORTS.list({ prefix, ...options });
		if (page.truncated && (!page.cursor || page.cursor === options.cursor)) throw new Error("non-progressing reports cursor");
		return Response.json({ keys: page.objects.filter(include).map((obj) => obj.key), cursor: page.truncated ? page.cursor : null });
	}
	const keys = [];
	let cursor, scanned = 0, pages = 0;
	do {
		if (++pages > LEGACY_LIST_PAGE_LIMIT) throw legacyOverflow("reports");
		const page = await env.REPORTS.list({ prefix, cursor, limit: 500 });
		scanned += page.objects.length;
		if (scanned > LEGACY_REPORT_SCAN_LIMIT) throw legacyOverflow("reports");
		keys.push(...page.objects.filter(include).map((obj) => obj.key));
		if (page.truncated && scanned >= LEGACY_REPORT_SCAN_LIMIT) throw legacyOverflow("reports");
		if (page.truncated && (!page.cursor || page.cursor === cursor)) throw new Error("non-progressing reports cursor");
		cursor = page.truncated ? page.cursor : undefined;
	} while (cursor);
	return legacyJson({ keys }, "reports");
}

async function getReport(request, env, url) {
	if (!authorizedReader(request, env)) return reply("unauthorized\n", 401);
	const key = url.searchParams.get("key") || "";
	if (!/^reports\/[a-z0-9][a-z0-9._-]{0,127}\/[^/\r\n]+\.json$/.test(key) || key.length > 400) return reply("bad key\n", 400);
	const obj = await env.REPORTS.get(key);
	if (!obj) return reply("not found\n", 404);
	return new Response(obj.body, { headers: { "content-type": "application/json" } });
}
function hostCursor(raw) {
	if (!raw) return { phase: "seen", cursor: undefined };
	try {
		if (!/^[A-Za-z0-9_-]+$/.test(raw)) throw new Error();
		const value = JSON.parse(atob(raw.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - raw.length % 4) % 4)));
		if (!plain(value) || value.v !== 1 || !["seen", "expected", "bootstrap"].includes(value.phase) || !Object.keys(value).every((k) => ["v", "phase", "cursor"].includes(k)) || (value.cursor !== null && (typeof value.cursor !== "string" || value.cursor.length > 4096 || /[^\x21-\x7e]/.test(value.cursor)))) throw new Error();
		return { phase: value.phase, cursor: value.cursor || undefined };
	} catch { throw new HttpError(400, "invalid hosts cursor"); }
}
function nextHostCursor(phase, cursor) {
	if (cursor !== null && (typeof cursor !== "string" || cursor.length > 4096 || /[^\x21-\x7e]/.test(cursor))) throw new Error("invalid KV cursor");
	return btoa(JSON.stringify({ v: 1, phase, cursor })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function hostRows(env, enrolled, phase, page, hosts) {
	for (const { name } of page.keys) {
		let host = name.slice(phase.length + 1);
		if (phase === "bootstrap") {
			const parts = host.split("/");
			if (parts.length !== 2 || !/^[a-f0-9]{64}$/.test(parts[1]) || enrolled.get(parts[0]) !== parts[1]) continue;
			host = parts[0];
		}
		if (!hostName(host) || !enrolled.has(host) || Object.hasOwn(hosts, host)) continue;
		try {
			const expected = await readExpected(env, host, enrolled.get(host), phase === "seen" ? "any" : phase === "expected" ? "shared" : "bootstrap");
			const seen = enrollmentSeen(await readSeen(env, host, enrolled.get(host), !expected), enrolled.get(host), !expected);
			if (phase === "seen") { if (seen) { const { enrollment: _enrollment, ...publicSeen } = seen; hosts[host] = publicSeen; } }
			else if (!seen && expected) {
				const receipt = await readSilenceReceipt(env, host, enrolled.get(host));
				hosts[host] = { at: expected.at, staleAlertedAt: receipt?.kind === "expected" && receipt.baselineAt === expected.at ? receipt.at : expected.staleAlertedAt || null, status: "awaiting-first-report" };
			}
		} catch { hosts[host] = { error: "unavailable or corrupt host state" }; }
	}
}
async function listHosts(request, env, url) {
	if (!authorizedReader(request, env)) return reply("unauthorized\n", 401);
	const hosts = Object.create(null);
	const enrolled = new Map(Object.entries(tokenConfig(env)).map(([hash, host]) => [host, hash]));
	if (paginated(url)) {
		const options = pageOptions(url, 8192);
		const { phase, cursor } = hostCursor(options.cursor);
		// At most four KV reads per marker plus the list, safely below the
		// invocation binding-operation ceiling even for a maximum-size page.
		const page = await env.STATE.list({ prefix: `${phase}/`, limit: Math.min(options.limit, 200), cursor });
		await hostRows(env, enrolled, phase, page, hosts);
		if (!page.list_complete && (!page.cursor || page.cursor === cursor)) throw new Error("non-progressing hosts cursor");
		const nextPhase = phase === "seen" ? "expected" : phase === "expected" ? "bootstrap" : null;
		const next = !page.list_complete ? nextHostCursor(phase, page.cursor) : nextPhase ? nextHostCursor(nextPhase, null) : null;
		return Response.json({ hosts, cursor: next });
	}
	let scanned = 0, pages = 0;
	for (const phase of ["seen", "expected", "bootstrap"]) {
		let cursor;
		do {
			if (++pages > LEGACY_LIST_PAGE_LIMIT) throw legacyOverflow("hosts");
			const page = await env.STATE.list({ prefix: `${phase}/`, limit: 100, cursor });
			scanned += page.keys.length;
			if (scanned > LEGACY_HOST_SCAN_LIMIT || (!page.list_complete && scanned >= LEGACY_HOST_SCAN_LIMIT)) throw legacyOverflow("hosts");
			await hostRows(env, enrolled, phase, page, hosts);
			if (!page.list_complete && (!page.cursor || page.cursor === cursor)) throw new Error("non-progressing hosts cursor");
			cursor = page.list_complete ? undefined : page.cursor;
		} while (cursor);
	}
	return legacyJson({ hosts }, "hosts");
}

function tokenConfig(env) {
	let tokens;
	try { tokens = JSON.parse(env.HOST_TOKENS); } catch { throw new HttpError(503, "HOST_TOKENS must be a JSON object mapping SHA-256 token hashes to host names"); }
	if (!plain(tokens) || Object.keys(tokens).length > 10000 || !Object.entries(tokens).every(([hash, host]) => /^[a-f0-9]{64}$/.test(hash) && hostName(host))) throw new HttpError(503, "invalid HOST_TOKENS configuration");
	if (new Set(Object.values(tokens)).size !== Object.keys(tokens).length) throw new HttpError(503, "HOST_TOKENS must contain exactly one active token per host");
	return tokens;
}
async function hostForToken(request, env) {
	const tokens = tokenConfig(env);
	const token = bearer(request);
	if (!token) return null;
	const hash = await sha256(token);
	return Object.hasOwn(tokens, hash) ? { host: tokens[hash], tokenHash: hash } : null;
}
function authorizedReader(request, env) {
	const token = bearer(request);
	return typeof env.READ_TOKEN === "string" && Boolean(env.READ_TOKEN && token && timingSafeEqual(token, env.READ_TOKEN));
}
function bearer(request) {
	const value = request.headers.get("authorization") || "";
	return value.startsWith("Bearer ") ? value.slice(7).trim() : null;
}
async function sha256(value) {
	return hex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}
const hex = (buffer) => [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function canaryMac(secret, host, tokenHash) {
	const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	return hex(await crypto.subtle.sign("HMAC", key, encoder.encode(`tattle-canary:${host}:${tokenHash}`)));
}
function timingSafeEqual(a, b) {
	if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return diff === 0;
}
async function notify(env, title, message, { priority = 3, tags = "" } = {}) {
	if (!env.NTFY_URL) return console.log("ntfy not configured:", title, message);
	const clean = title.replace(/[\r\n]+/g, " ");
	const asciiTitle = clean.replace(/[^\x20-\x7e]/g, "?").slice(0, 200);
	const headers = { Title: asciiTitle, Priority: String(priority), Tags: tags };
	if (env.NTFY_TOKEN) headers.Authorization = `Bearer ${env.NTFY_TOKEN}`;
	const res = await fetch(env.NTFY_URL, { method: "POST", body: truncateUtf8(`${clean}\n\n${message}`, 3800), headers });
	if (!res.ok) throw new Error(`ntfy failed: ${res.status}`);
}
function truncateUtf8(value, limit) {
	const bytes = encoder.encode(value);
	return bytes.byteLength <= limit ? value : new TextDecoder().decode(bytes.slice(0, limit), { stream: true });
}
function validOrigin(value) {
	let url;
	try { url = new URL(value); } catch { throw new HttpError(400, "invalid worker HTTPS origin"); }
	const safeHost = url.hostname.startsWith("[") ? /^\[[a-f0-9:]+\]$/i.test(url.hostname) : url.hostname.length <= 253 && url.hostname.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
	if (url.protocol !== "https:" || url.username || url.password || url.origin !== value || !safeHost || (url.port && !/^\d{1,5}$/.test(url.port))) throw new HttpError(400, "invalid worker HTTPS origin");
	return url.origin;
}
const shellSingleQuoteContent = (value) => value.replace(/'/g, "'\\''");
function errorResponse(err) {
	if (err instanceof HttpError) return reply(`${err.message}\n`, err.status);
	console.error(err);
	return reply("dependency failure; retry the same request\n", 503);
}
