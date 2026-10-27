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
	assert.deepEqual(out, ["~ posture: filevault: FileVault is Off.", "- posture: filevault: FileVault is On."]);
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

const validCanaries = () => ({
	aws: { aws_access_key_id: "AKIAEXAMPLE123", aws_secret_access_key: "aB09+/=._-secret", region: "us-east-2" },
	envFile: { aws_access_key_id: "AKIAEXAMPLE456", aws_secret_access_key: "other+/=secret", region: "us-gov-west-1" },
	dns: { hostname: "abc-123.canarytokens.com" },
});

test("posture deletion and empty posture alert; reorder and duplicate lines stay quiet", () => {
	assert.deepEqual(diffSections(base, { ...base, posture: "firewall: enabled" }), ["- posture: filevault: FileVault is On."]);
	assert.deepEqual(diffSections(base, { ...base, posture: "" }), ["- posture: filevault: FileVault is On.", "- posture: firewall: enabled"]);
	assert.deepEqual(diffSections(base, { ...base, posture: "firewall: enabled\r\nfilevault: FileVault is On.\nfirewall: enabled\n" }), []);
	assert.deepEqual(diffSections(base, { ...base, accounts: "", ssh: "", persistence: "" }), []);
});

test("legacy and hostile diff inputs never invoke coercion or throw", () => {
	const hostile = { toString() { throw new Error("coerced"); }, valueOf() { throw new Error("coerced"); } };
	const getter = new Proxy({}, { get() { throw new Error("getter"); } });
	for (const value of [undefined, null, false, 12, [], hostile, getter, Symbol("bad")]) {
		assert.deepEqual(diffSections(value, value), []);
		const sections = { accounts: value, ssh: value, persistence: value, posture: value, listening: value };
		assert.deepEqual(diffSections(sections, sections), []);
		assert.doesNotThrow(() => diffSections(base, sections));
		assert.doesNotThrow(() => diffSections(sections, base));
	}
});

test("plant script rejects current shell injection payloads", () => {
	for (const payload of ["AKIA$(rm -rf ~)", "x`y`", "x\nCANARY\nreboot", "abc.canarytokens.com;reboot"]) {
		for (const [section, field] of [["aws", "aws_access_key_id"], ["envFile", "aws_secret_access_key"], ["dns", "hostname"]]) {
			const values = validCanaries();
			values[section][field] = payload;
			assert.throws(() => plantScript(values), /invalid or missing field/);
		}
	}
});

test("provider fields reject objects, arrays, numbers, blanks and malformed hostnames", () => {
	for (const value of [undefined, null, {}, [], 1, true, "", " ", { toString() { throw new Error("coerced"); } }]) {
		for (const [section, field] of [["aws", "aws_access_key_id"], ["aws", "aws_secret_access_key"], ["envFile", "aws_access_key_id"], ["envFile", "aws_secret_access_key"], ["dns", "hostname"], ["aws", "region"]]) {
			if (field === "region" && value === undefined) continue;
			const values = validCanaries();
			values[section][field] = value;
			assert.throws(() => plantScript(values), /invalid or missing field/);
		}
		assert.throws(() => plantScript(value), /invalid or missing field/);
		for (const section of ["aws", "envFile", "dns"]) assert.throws(() => plantScript({ ...validCanaries(), [section]: value }), /invalid or missing field/);
	}
	for (const hostname of ["localhost", "127.0.0.1", "https://abc.canarytokens.com", "abc..com", "-abc.com", "abc-.com", "abc.com/path", "abc.com:53", "*.example.com", "a".repeat(64) + ".com"]) {
		assert.throws(() => plantScript({ ...validCanaries(), dns: { hostname } }), /invalid or missing field/);
	}
});

test("representative provider values and optional region render unchanged", () => {
	const values = validCanaries();
	delete values.aws.region;
	values.dns.hostname = "AbC-123.canarytokens.org.";
	const script = plantScript(values);
	assert.ok(script.startsWith("#!/bin/sh\n"));
	assert.ok(script.includes("aws_secret_access_key = aB09+/=._-secret"));
	assert.ok(script.includes("region = us-east-2"));
	assert.ok(script.includes("AWS_DEFAULT_REGION=us-gov-west-1"));
	assert.ok(script.includes("HostName AbC-123.canarytokens.org."));
	assert.ok(script.includes("[backup-admin]"));
	assert.ok(script.includes("Host db-backup-prod"));
});

import { mkdtempSync, readFileSync, statSync, realpathSync, mkdirSync, writeFileSync, symlinkSync, linkSync, readdirSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

test("plant script preserves locations, restricted modes and idempotent output", () => {
	const home = realpathSync(mkdtempSync(join(tmpdir(), "tattle-canary-test-")));
	const run = () => spawnSync("/bin/sh", [], { input: plantScript(validCanaries()), env: { ...process.env, HOME: home }, encoding: "utf8" });
	const first = run();
	assert.equal(first.status, 0, first.stderr);
	assert.equal(first.stdout, "tattle canaries: ~/.aws/credentials ~/Documents/prod-secrets.env ~/.ssh/config\n");
	const paths = [".aws/credentials", "Documents/prod-secrets.env", ".ssh/config"].map((path) => join(home, path));
	const contents = paths.map((path) => readFileSync(path, "utf8"));
	for (const path of paths) assert.equal(statSync(path).mode & 0o777, 0o600);
	const second = run();
	assert.equal(second.status, 0, second.stderr);
	assert.equal(second.stdout, "tattle canaries: already planted\n");
	assert.deepEqual(paths.map((path) => readFileSync(path, "utf8")), contents);
});

import { mintCanaries } from "../src/canaries.js";

test("mint validates provider responses and supports scoped and legacy callback keys", async (t) => {
	const requests = [];
	let malformed = false;
	t.mock.method(globalThis, "fetch", async (_url, options) => {
		const request = JSON.parse(options.body);
		requests.push(request);
		return { ok: true, json: async () => malformed ? [] : request.token_type === "dns" ? validCanaries().dns : validCanaries().aws };
	});
	await mintCanaries({ CANARY_KEY: "legacy" }, "https://worker.example", "host", "host:scoped/key");
	assert.equal(requests.length, 3);
	for (const request of requests) assert.equal(request.webhook_url, "https://worker.example/canary?key=host%3Ascoped%2Fkey");
	requests.length = 0;
	await mintCanaries({ CANARY_KEY: "legacy" }, "https://worker.example", "host");
	for (const request of requests) assert.equal(request.webhook_url, "https://worker.example/canary?key=legacy");
	malformed = true;
	await assert.rejects(mintCanaries({ CANARY_KEY: "legacy" }, "https://worker.example", "host"), /provider response failed/);
});

const canaryHome = () => realpathSync(mkdtempSync(join(tmpdir(), "tattle-refresh-test-")));
const canaryPaths = (home) => [".aws/credentials", "Documents/prod-secrets.env", ".ssh/config"].map((path) => join(home, path));
const runCanaries = (home, values = validCanaries(), refresh = true) => spawnSync("/bin/sh", ["-s", "--", ...(refresh ? ["--refresh"] : [])], {
	input: plantScript(values), env: { ...process.env, HOME: home }, encoding: "utf8",
});
const seedCanaries = (home, aws, env, ssh) => {
	for (const dir of [".aws", "Documents", ".ssh"]) mkdirSync(join(home, dir), { mode: 0o700 });
	for (const [index, text] of [aws, env, ssh].entries()) if (text !== undefined) writeFileSync(canaryPaths(home)[index], text, { mode: 0o600 });
};
const legacyAws = "# tattle-canary: do not use\n[backup-admin]\naws_access_key_id = AKIAOLD\naws_secret_access_key = oldsecret\nregion = us-east-2\n";
const legacySsh = "# tattle-canary: do not use\nHost db-backup-prod\n  HostName old.canarytokens.com\n  User root\n";
const legacyEnv = "# production backup credentials (rotated quarterly)\nAWS_ACCESS_KEY_ID=AKIAOLD\nAWS_SECRET_ACCESS_KEY=oldsecret\nAWS_DEFAULT_REGION=us-east-2\nS3_BACKUP_BUCKET=prod-db-backups\n";

test("explicit refresh migrates exact legacy AWS/SSH blocks, preserves unrelated bytes and backs up originals", () => {
	const home = canaryHome();
	const awsPrefix = "# personal credentials\r\n[personal]\r\naws_access_key_id = PERSONAL\r\n\n";
	const awsSuffix = "\n# retain whitespace  \n[work]\naws_access_key_id = WORK";
	const sshPrefix = "# personal hosts\r\nHost laptop\r\n  HostName laptop.local\r\n\n";
	const sshSuffix = "\n# retain this too\nHost other\n  HostName other.local";
	const originals = [awsPrefix + legacyAws + awsSuffix, undefined, sshPrefix + legacySsh + sshSuffix];
	seedCanaries(home, ...originals);
	const first = runCanaries(home);
	assert.equal(first.status, 0, first.stderr);
	for (const [index, prefix, suffix] of [[0, awsPrefix, awsSuffix], [2, sshPrefix, sshSuffix]]) {
		const file = canaryPaths(home)[index];
		const text = readFileSync(file, "utf8");
		assert.ok(text.startsWith(prefix));
		assert.ok(text.endsWith(suffix));
		assert.ok(!text.includes("AKIAOLD") && !text.includes("old.canarytokens.com"));
		const backups = readdirSync(join(file, "..")).filter((name) => name.startsWith(".tattle-canary-backup."));
		assert.equal(backups.length, 1);
		assert.equal(readFileSync(join(file, "..", backups[0]), "utf8"), originals[index]);
		assert.equal(statSync(join(file, "..", backups[0])).mode & 0o777, 0o600);
	}
	const before = canaryPaths(home).map((file) => readFileSync(file));
	const next = runCanaries(home);
	assert.equal(next.status, 0, next.stderr);
	assert.equal(next.stdout, "tattle canaries: already planted\n");
	assert.deepEqual(canaryPaths(home).map((file) => readFileSync(file)), before);
	for (const dir of [".aws", ".ssh"]) assert.equal(readdirSync(join(home, dir)).filter((name) => name.startsWith(".tattle-canary-backup.")).length, 1);
	assert.ok(!first.stdout.includes(validCanaries().aws.aws_access_key_id));
});

test("refresh updates marked current files with newly scoped credentials and then converges", () => {
	const home = canaryHome();
	assert.equal(runCanaries(home, validCanaries(), false).status, 0);
	const next = validCanaries();
	next.aws.aws_access_key_id = "AKIAREPLACED";
	next.envFile.aws_access_key_id = "AKIAENVREPLACED";
	next.dns.hostname = "replacement.canarytokens.com";
	const refreshed = runCanaries(home, next);
	assert.equal(refreshed.status, 0, refreshed.stderr);
	for (const [file, expected] of canaryPaths(home).map((file, i) => [file, ["AKIAREPLACED", "AKIAENVREPLACED", "replacement.canarytokens.com"][i]])) assert.ok(readFileSync(file, "utf8").includes(expected));
	assert.equal(runCanaries(home, next).stdout, "tattle canaries: already planted\n");
});

test("refresh refuses unmarked env files including the generic legacy template before any credential change", () => {
	for (const env of [legacyEnv, "MY_REAL_SECRET=preserve-me\n", ""]) {
		const home = canaryHome();
		seedCanaries(home, legacyAws, env, legacySsh);
		const result = runCanaries(home);
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /cannot establish Tattle ownership:.*prod-secrets.env/);
		assert.match(result.stderr, /manually migrate only confirmed old Tattle canaries/);
		assert.deepEqual(canaryPaths(home).map((file) => readFileSync(file, "utf8")), [legacyAws, env, legacySsh]);
		assert.ok(!readdirSync(join(home, ".aws")).some((name) => name.startsWith(".tattle-canary-backup.")));
	}
});

test("refresh rejects ambiguous, duplicate, modified or unmarked target sections", () => {
	for (const [aws, ssh] of [
		[legacyAws + "output = json\n", legacySsh],
		[legacyAws + "\n" + legacyAws, legacySsh],
		[legacyAws.replace("[backup-admin]", "[real-admin]"), legacySsh],
		[legacyAws.replace("# tattle-canary: do not use\n", ""), legacySsh],
		[legacyAws, legacySsh + "  IdentityFile ~/.ssh/real\n"],
		[legacyAws, legacySsh + "\nHost db-backup-prod other\n  User human\n"],
		[legacyAws, legacySsh.replace("# tattle-canary: do not use\n", "")],
	]) {
		const home = canaryHome();
		seedCanaries(home, aws, undefined, ssh);
		const result = runCanaries(home);
		assert.notEqual(result.status, 0, JSON.stringify([aws, ssh]));
		assert.match(result.stderr, /cannot establish Tattle ownership/);
		assert.equal(readFileSync(canaryPaths(home)[0], "utf8"), aws);
		assert.equal(readFileSync(canaryPaths(home)[2], "utf8"), ssh);
	}
});

test("refresh rejects symlink, dangling and hardlinked files at every canary location", () => {
	for (const attack of ["symlink", "dangling", "hardlink"]) for (const index of [0, 1, 2]) {
		const home = canaryHome();
		seedCanaries(home);
		const outside = join(home, "outside");
		writeFileSync(outside, "preserve me\n", { mode: 0o600 });
		if (attack === "hardlink") linkSync(outside, canaryPaths(home)[index]);
		else symlinkSync(attack === "symlink" ? outside : join(home, "missing"), canaryPaths(home)[index]);
		const result = runCanaries(home);
		assert.notEqual(result.status, 0, attack);
		assert.match(result.stderr, /symlink refused|hardlink refused/);
		assert.equal(readFileSync(outside, "utf8"), "preserve me\n");
		for (const other of [0, 1, 2].filter((other) => other !== index)) assert.ok(!readdirSync(join(canaryPaths(home)[other], "..")).some((name) => !name.startsWith(".")));
	}
});

test("refresh rejects directory symlinks, noncanonical HOME and writable homes/directories", () => {
	for (const dir of [".aws", ".ssh", "Documents"]) {
		const home = canaryHome();
		const outside = join(home, "outside");
		mkdirSync(outside, { mode: 0o700 });
		writeFileSync(join(outside, "sentinel"), "untouched");
		symlinkSync(outside, join(home, dir));
		const result = runCanaries(home);
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /symlink refused/);
		assert.deepEqual(readdirSync(outside), ["sentinel"]);
	}
	for (const attack of ["alias", "dotdot", "home-mode", "directory-mode"]) {
		const home = canaryHome();
		seedCanaries(home, legacyAws, undefined, legacySsh);
		let target = home;
		if (attack === "alias") { target = join(home, "linked-home"); symlinkSync(home, target); }
		if (attack === "dotdot") target += "/../" + home.split("/").at(-1);
		if (attack === "home-mode") chmodSync(home, 0o777);
		if (attack === "directory-mode") chmodSync(join(home, ".aws"), 0o777);
		const result = runCanaries(target);
		assert.notEqual(result.status, 0, attack);
		assert.equal(readFileSync(canaryPaths(home)[0], "utf8"), legacyAws);
		assert.equal(readFileSync(canaryPaths(home)[2], "utf8"), legacySsh);
	}
});

test("Darwin's exact OS /var HOME alias supports planting and refresh", { skip: process.platform !== "darwin" }, () => {
	const home = canaryHome();
	assert.ok(home.startsWith("/private/var/"));
	const alias = home.replace(/^\/private\/var\//, "/var/");
	const planted = runCanaries(alias, validCanaries(), false);
	assert.equal(planted.status, 0, planted.stderr);
	const refreshed = runCanaries(alias);
	assert.equal(refreshed.status, 0, refreshed.stderr);
	assert.equal(refreshed.stdout, "tattle canaries: already planted\n");
});

test("invalid generated-script arguments fail before creating any canary directories", () => {
	for (const args of [["--unknown"], ["--refresh", "extra"]]) {
		const home = canaryHome();
		const result = spawnSync("/bin/sh", ["-s", "--", ...args], { input: plantScript(validCanaries()), env: { ...process.env, HOME: home }, encoding: "utf8" });
		assert.notEqual(result.status, 0);
		assert.deepEqual(readdirSync(home), []);
	}
});

test("refresh safely appends to unrelated AWS/SSH files without changing existing bytes", () => {
	const home = canaryHome();
	const aws = "[personal]\naws_access_key_id = PERSONAL";
	const ssh = "Host personal\n  HostName personal.local";
	seedCanaries(home, aws, undefined, ssh);
	const result = runCanaries(home);
	assert.equal(result.status, 0, result.stderr);
	assert.ok(readFileSync(canaryPaths(home)[0], "utf8").startsWith(aws + "\n"));
	assert.ok(readFileSync(canaryPaths(home)[2], "utf8").startsWith(ssh + "\n"));
});
