import { test } from "node:test";
import assert from "node:assert/strict";
import { diffSections } from "../src/diff.js";

const base = {
	accounts: "admin: alice root\nuser: alice 501",
	ssh: "remote-login: Off",
	persistence: "abc /Library/LaunchDaemons/a.plist",
	posture: "filevault: FileVault is On.\nfirewall: enabled",
	listening: "Dropbox alice *:17500\nbb alice 127.0.0.1:38886",
	packages: "Foo.app 1.0",
};

test("no change, no findings", () => {
	assert.deepEqual(diffSections(base, { ...base }), []);
});

test("new admin, ssh key and launch daemon alert", () => {
	const after = {
		...base,
		accounts: "admin: alice evil root\nuser: alice 501",
		ssh: "remote-login: Off\nroot SHA256:xyz key",
		persistence: base.persistence + "\ndef /Library/LaunchDaemons/evil.plist",
	};
	const out = diffSections(base, after);
	assert.equal(out.length, 3);
	assert.ok(out.some((l) => l.includes("evil.plist")));
});

test("posture regression alerts", () => {
	const out = diffSections(base, { ...base, posture: "filevault: FileVault is Off.\nfirewall: enabled" });
	assert.deepEqual(out, ["~ posture: filevault: FileVault is Off."]);
});

test("loopback and port churn are ignored; new exposed process alerts", () => {
	const quiet = { ...base, listening: "Dropbox alice *:17501\nbb alice 127.0.0.1:40000\nnode alice 127.0.0.1:3000" };
	assert.deepEqual(diffSections(base, quiet), []);
	const loud = { ...base, listening: base.listening + "\nnc alice *:4444" };
	assert.deepEqual(diffSections(base, loud), ["+ listening: nc now accepts connections from the network"]);
});

test("linux ss lines parse the process name", () => {
	const before = { ...base, listening: "tcp 0.0.0.0:22 sshd" };
	const after = { ...base, listening: "tcp 0.0.0.0:22 sshd\ntcp [::]:8080 python3\ntcp 127.0.0.1:5432 postgres" };
	assert.deepEqual(diffSections(before, after), ["+ listening: python3 now accepts connections from the network"]);
});

test("package changes never alert", () => {
	assert.deepEqual(diffSections(base, { ...base, packages: "Foo.app 2.0\nBar.app 1.0" }), []);
});

import { plantScript } from "../src/canaries.js";

test("plant script strips shell metacharacters from token values", () => {
	const evil = { aws_access_key_id: "AKIA$(rm -rf ~)", aws_secret_access_key: "x`y`", region: "us-east-2" };
	const script = plantScript({ aws: evil, envFile: evil, dns: { hostname: "abc.canarytokens.com;reboot" } });
	assert.ok(!script.includes("$(rm"));
	assert.ok(!script.includes("`y`"));
	assert.ok(script.includes("HostName abc.canarytokens.comreboot"));
});

test("plantScript refuses blank canary values", () => {
	const aws = { aws_access_key_id: "", aws_secret_access_key: "x" };
	assert.throws(() => plantScript({ aws, envFile: aws, dns: { hostname: "h.example" } }));
});

test("alertMime builds a plain-text message with an encoded subject", async () => {
	const { alertMime } = await import("../src/email.js");
	const raw = alertMime({ from: "tattle@example.com", to: "a@example.org", subject: "box: 2 changes\nX-Injected: 1", body: "new admin: mallory", id: "abc" });
	assert.match(raw, /^From: tattle <tattle@example.com>\r\n/);
	assert.match(raw, /\r\nMessage-ID: <abc@example.com>\r\n/);
	assert.doesNotMatch(raw, /\r\nX-Injected/);
	const [, body] = raw.split("\r\n\r\n");
	assert.equal(Buffer.from(body, "base64").toString(), "new admin: mallory");
});
