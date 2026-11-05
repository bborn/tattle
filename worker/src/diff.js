// Sections where a new line is worth waking someone up for.
const ALERT_ON_ADD = ["accounts", "ssh", "persistence"];
// Sections where any change at all is worth an alert.
const ALERT_ON_ANY_CHANGE = ["posture"];

// Returns human-readable lines describing the changes worth alerting on.
export function diffSections(before, after) {
	const out = [];
	const lines = (s) => new Set(String(s || "").split("\n").filter(Boolean));

	for (const name of ALERT_ON_ADD) {
		const old = lines(before[name]);
		for (const line of lines(after[name])) if (!old.has(line)) out.push(`+ ${name}: ${line}`);
	}
	for (const name of ALERT_ON_ANY_CHANGE) {
		const old = lines(before[name]);
		const cur = lines(after[name]);
		for (const line of cur) if (!old.has(line)) out.push(`~ ${name}: ${line}`);
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
	const oldExposed = exposed(before.listening);
	for (const proc of exposed(after.listening)) {
		if (!oldExposed.has(proc)) out.push(`+ listening: ${proc} now accepts connections from the network`);
	}
	return out;
}

// Sections that flap: an app that isn't running when a snapshot is taken (just
// after a reboot, say) drops out and then looks "new" the next day. For these,
// anything a host has ever reported counts as already seen, so each listener or
// launch agent alerts once. Persistence lines carry a content hash, so editing
// a plist still alerts.
export const REMEMBERED = ["persistence", "listening"];
const KNOWN_CAP = 2000;

// Previous sections with every line this host has ever reported folded in.
export function withKnown(previous, known) {
	const merged = { ...previous };
	for (const name of REMEMBERED) {
		const extra = (known && known[name]) || [];
		if (extra.length) merged[name] = [String(previous[name] || ""), ...extra].filter(Boolean).join("\n");
	}
	return merged;
}

// The known set after adding this report's lines. Newest lines are kept when
// the cap is hit, so something long gone can eventually alert again.
export function rememberSeen(known, sections) {
	const out = {};
	for (const name of REMEMBERED) {
		const set = new Set((known && known[name]) || []);
		for (const line of String(sections[name] || "").split("\n").filter(Boolean)) {
			set.delete(line);
			set.add(line);
		}
		out[name] = [...set].slice(-KNOWN_CAP);
	}
	return out;
}
