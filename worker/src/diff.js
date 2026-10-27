// Sections where a new line is worth waking someone up for.
const ALERT_ON_ADD = ["accounts", "ssh", "persistence"];
// Sections where any change at all is worth an alert.
const ALERT_ON_ANY_CHANGE = ["posture"];

// Returns human-readable lines describing the changes worth alerting on.
export function diffSections(before, after) {
	const out = [];
	// Legacy snapshots can contain arbitrary JSON values. Never coerce them:
	// coercion can execute user-defined toString/valueOf methods.
	const field = (sections, name) => {
		try { return sections?.[name]; } catch { return undefined; }
	};
	const lines = (s) => new Set(typeof s === "string" ? s.split("\n").map((line) => line.trim()).filter(Boolean) : []);

	for (const name of ALERT_ON_ADD) {
		const old = lines(field(before, name));
		for (const line of lines(field(after, name))) if (!old.has(line)) out.push(`+ ${name}: ${line}`);
	}
	for (const name of ALERT_ON_ANY_CHANGE) {
		const old = lines(field(before, name));
		const cur = lines(field(after, name));
		for (const line of cur) if (!old.has(line)) out.push(`~ ${name}: ${line}`);
		for (const line of old) if (!cur.has(line)) out.push(`- ${name}: ${line}`);
	}

	// Listening sockets: ports on loopback and ephemeral ports churn constantly.
	// Alert only when a process starts listening on a non-loopback address it
	// was not listening on before.
	const exposed = (s) => {
		const set = new Set();
		for (const line of lines(s)) {
			const parts = line.split(" ");
			const addr = parts.find((p) => p.includes(":")) || "";
			if (/^(127\.|\[::1\]|::1|localhost)/.test(addr)) continue;
			const proc = parts.find((p) => p && !p.includes(":") && !/^(tcp|udp|LISTEN|UNCONN)$/i.test(p)) || "?";
			set.add(proc);
		}
		return set;
	};
	const oldExposed = exposed(field(before, "listening"));
	for (const proc of exposed(field(after, "listening"))) {
		if (!oldExposed.has(proc)) out.push(`+ listening: ${proc} now accepts connections from the network`);
	}
	return out;
}
