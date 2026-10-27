#!/bin/sh
# Offline operator tests. All remote commands and HTTP requests are stubbed.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
python3 - "$ROOT" <<'PY'
import json, os, pathlib, re, stat, subprocess, sys, tempfile
root = pathlib.Path(sys.argv[1])
with tempfile.TemporaryDirectory(prefix="tattle-cli-hardening-") as raw:
    work = pathlib.Path(raw).resolve()
    deploy, stubs = work / "deploy", work / "stubs"
    deploy.mkdir(mode=0o700); stubs.mkdir(mode=0o700)
    secrets = work / "secrets.env"
    secrets.write_text("TATTLE_URL=https://example.invalid\nREAD_TOKEN=reader-secret-unique\nCANARY_KEY=canary-secret-unique\nNTFY_URL=https://ntfy.invalid/private\nHEARTBEAT_URL=\nCANARY_EMAIL=\nNTFY_TOKEN=\n")
    secrets.chmod(0o600)
    valid_config = '''name = "test"
main = "src/index.js"
[[durable_objects.bindings]]
name = "HOST_GATE"
class_name = "HostGate"
[[migrations]]
tag = "v1-host-gate"
new_sqlite_classes = ["HostGate"]
'''
    (deploy / "wrangler.toml").write_text(valid_config)
    (deploy / "hosts.json").write_text('{}\n')
    remote = work / "remote.json"
    remote.write_text(json.dumps({"secrets": {"HOST_TOKENS":"{}", "HEARTBEAT_URL":"old", "CANARY_EMAIL":"old", "NTFY_TOKEN":"old"}, "kv":{}}))
    log = work / "calls.jsonl"
    stub = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
work = pathlib.Path(os.environ["STUB_WORK"])
args = sys.argv[1:]
data = sys.stdin.read()
with (work / "calls.jsonl").open("a") as f: f.write(json.dumps({"tool":pathlib.Path(sys.argv[0]).name,"argv":args,"stdin":data})+"\n")
def fail_once(marker):
    p=work / marker
    if p.exists():
        p.unlink(); print("synthetic remote failure: " + marker, file=sys.stderr); sys.exit(1)
if pathlib.Path(sys.argv[0]).name == "curl":
    assert "--config" in args and args[args.index("--config")+1] == "-"
    url=args[-1]
    if "/hosts" in url:
        assert "Authorization: Bearer reader-secret-unique" in data
        if "STUB_STATUS_RESPONSE" in os.environ:
            print(os.environ["STUB_STATUS_RESPONSE"]); sys.exit(0)
        if "cursor=" in url:
            assert url.endswith("?pagination=1&cursor=next%2Fpage")
            print(json.dumps({"hosts":{"second":{"at":"2026-10-01T00:00:00Z"},"new-host":{"at":"2026-10-02T03:04:00Z","status":"awaiting-first-report"},"bad-host":{"error":"unavailable or corrupt host state"}},"cursor":None}))
        else:
            assert url.endswith("?pagination=1")
            print(json.dumps({"hosts":{"first":{"at":"2026-10-01T00:00:00Z"}},"cursor":"next/page"}))
    elif url.endswith("/canary"):
        assert "Authorization: Bearer canary-secret-unique" in data
        print("{}")
    else: raise AssertionError(url)
    sys.exit(0)
assert args[0] == "--config"
config=pathlib.Path(args[1]); assert config.parent == pathlib.Path(os.environ["TEST_ROOT"]) / "worker"
assert config.stat().st_mode & 0o777 == 0o600
args=args[2:]
p=work / "remote.json"; remote=json.loads(p.read_text())
if args[:2] == ["secret","put"]:
    if args[2] == "HOST_TOKENS" and json.loads(data) == {}: fail_once("fail-revoke-once")
    remote["secrets"][args[2]]=data
    if args[2] == "HOST_TOKENS" and json.loads(data):
        p.write_text(json.dumps(remote)); fail_once("fail-add-once")
elif args[:2] == ["secret","list"]:
    fail_once("fail-list-once")
    print(json.dumps([{"name":k,"type":"secret_text"} for k in remote["secrets"]]))
elif args[:2] == ["secret","delete"]:
    fail_once("fail-delete-once")
    assert data.strip() == "y"
    remote["secrets"].pop(args[2],None)
elif args[:3] == ["kv","key","put"]:
    key,value=args[-2:]
    remote["kv"][key]=value
    # Model an ambiguous request: the remote write succeeds before an error.
    p.write_text(json.dumps(remote))
    fail_once("fail-enroll-once")
elif args[:3] == ["kv","key","delete"]:
    fail_once("fail-cleanup-once")
    remote["kv"].pop(args[-1],None)
elif args == ["deploy", "--dry-run"]:
    fail_once("fail-dry-run-once")
    sys.exit(0)
elif args == ["deploy"]: pass
else: raise AssertionError(args)
p.write_text(json.dumps(remote))
'''
    for name in ("wrangler", "curl"):
        p = stubs / name; p.write_text(stub); p.chmod(0o700)
    env = dict(os.environ, TATTLE_DEPLOY=str(deploy), TATTLE_SECRETS=str(secrets), WRANGLER=str(stubs / "wrangler"), STUB_WORK=str(work), TEST_ROOT=str(root), PATH=str(stubs)+os.pathsep+os.environ["PATH"])
    def run(*args, ok=True, extra=None):
        actual = dict(env); actual.update(extra or {})
        result = subprocess.run(["sh",str(root / "bin/tattle"),*args], env=actual, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        assert (result.returncode == 0) == ok, (args,result.returncode,result.stdout,result.stderr)
        assert not list((root / "worker").glob(".tattle-wrangler-*.toml")), "temporary Wrangler configuration retained"
        return result
    def state(): return json.loads(remote.read_text())
    def hosts(): return json.loads((deploy / "hosts.json").read_text())
    def marker(name): (work / name).touch()
    def calls(): return [json.loads(v) for v in log.read_text().splitlines()] if log.exists() else []

    result = run("status")
    assert "first" in result.stdout and "second" in result.stdout
    lines = {line.split()[0]:line for line in result.stdout.splitlines()}
    assert "h ago  2026-10-01 00:00 UTC" in lines["first"]
    assert "h ago  2026-10-01 00:00 UTC" in lines["second"]
    assert "awaiting first report since enrollment  2026-10-02 03:04 UTC" in lines["new-host"]
    assert "h ago" not in lines["new-host"]
    assert lines["bad-host"].endswith("unavailable: unavailable or corrupt host state")
    run("test-alert")
    for call in calls():
        assert "reader-secret-unique" not in " ".join(call["argv"])
        assert "canary-secret-unique" not in " ".join(call["argv"])
    assert len([c for c in calls() if c["tool"] == "curl" and "/hosts" in c["argv"][-1]]) == 2

    # Corrupt remote entries have controlled errors; other response corruption
    # must fail clearly rather than being mistaken for a successful status read.
    bounded = run("status", extra={"STUB_STATUS_RESPONSE":json.dumps({"hosts":{"broken":{"error":"remote\n\x1b " + "x"*300}}})})
    error_text = bounded.stdout.strip().split("unavailable: ",1)[1]
    assert len(error_text) == 160 and "\x1b" not in error_text and "\n" not in error_text
    malformed = [[], {"hosts":[]}, {"hosts":{"broken":None}}, {"hosts":{"broken":[]}},
        {"hosts":{"broken":{}}}, {"hosts":{"broken":{"at":42}}},
        {"hosts":{"broken":{"at":"not-a-timestamp"}}},
        {"hosts":{"broken":{"at":"2026-10-01T00:00:00"}}},
        {"hosts":{"broken":{"error":""}}}, {"hosts":{"broken":{"error":42}}},
        {"hosts":{}, "cursor":0}]
    for response in malformed:
        rejected = run("status", ok=False, extra={"STUB_STATUS_RESPONSE":json.dumps(response)})
        assert "tattle:" in rejected.stderr and "Traceback" not in rejected.stderr

    # Status works against legacy workers that ignore the pagination opt-in,
    # including ordinary host names that overlap response envelope fields.
    for legacy in ({"old-host":{"at":"2026-10-01T00:00:00Z"}},
            {"hosts":{"at":"2026-10-01T00:00:00Z"}},
            {"cursor":{"at":"2026-10-01T00:00:00Z"}}, {}):
        result = run("status", extra={"STUB_STATUS_RESPONSE":json.dumps(legacy)})
        assert all(name in result.stdout for name in legacy)
    repeated = run("status", ok=False, extra={"STUB_STATUS_RESPONSE":json.dumps({"hosts":{}, "cursor":"same"})})
    assert "repeated hosts cursor" in repeated.stderr

    # Invalid operator input or edited local state must never publish a partial
    # or poisoned token map, nor create enrollment state.
    def rejects_without_remote_change(*command):
        before_remote = remote.read_bytes()
        before_hosts = (deploy / "hosts.json").read_bytes()
        before_pending = (deploy / ".tattle-pending.json").read_bytes() if (deploy / ".tattle-pending.json").exists() else None
        before_calls = len(calls())
        rejected = run(*command, ok=False)
        assert "tattle:" in rejected.stderr
        assert remote.read_bytes() == before_remote and len(calls()) == before_calls
        assert (deploy / "hosts.json").read_bytes() == before_hosts
        after_pending = (deploy / ".tattle-pending.json").read_bytes() if (deploy / ".tattle-pending.json").exists() else None
        assert after_pending == before_pending
    for name in ("constructor", "prototype", "__proto__", "x"*129, "Uppercase", "bad_name"):
        rejects_without_remote_change("add-host", name)
        rejects_without_remote_change("remove-host", name)
    poisoned_maps = [{name:"a"*64} for name in ("constructor", "prototype", "__proto__", "x"*129)]
    poisoned_maps += [{"first":"a"*64,"second":"a"*64}, {"safe-host":"invalid-hash"},
        {f"host-{i}":f"{i:064x}" for i in range(10001)}]
    for poisoned in poisoned_maps:
        (deploy / "hosts.json").write_text(json.dumps(poisoned))
        for command in (("deploy",), ("add-host","safe-host"), ("remove-host","safe-host")):
            rejects_without_remote_change(*command)
        (deploy / "hosts.json").write_text("{}")
        # Validate both sides of every pending transaction before recovery can
        # publish even an otherwise valid rollback or desired-state map.
        for field in ("old", "target"):
            journal = {"op":"add", "name":"safe-host", "old":{}, "target":{"safe-host":"b"*64}, "at":"2026-10-01T00:00:00Z"}
            journal[field] = poisoned
            (deploy / ".tattle-pending.json").write_text(json.dumps(journal))
            rejects_without_remote_change("deploy")
            (deploy / ".tattle-pending.json").unlink()
    # The existing map can reach the cap, but an add must reject host 10001
    # before writing a journal or making any remote call.
    (deploy / "hosts.json").write_text(json.dumps({f"host-{i}":f"{i:064x}" for i in range(10000)}))
    rejects_without_remote_change("add-host", "host-over-limit")
    (deploy / "hosts.json").write_text("{}")
    # Length boundary and ordinary dotted/dashed names retain enrollment support.
    for name in ("x"*128, "constructor-node.example"):
        run("add-host", name)
        assert name in hosts()
        run("remove-host", name)
        assert hosts() == {} and state()["kv"] == {}

    added = run("add-host", "host-one")
    assert "--prompt-token" in added.stdout
    digest = hosts()["host-one"]
    assert re.fullmatch("[a-f0-9]{64}", digest)
    token = re.search(r"\n  ([a-f0-9]{64})\n", added.stdout).group(1)
    assert added.stdout.count(token) == 1 and token not in (deploy / "hosts.json").read_text()
    assert json.loads(state()["secrets"]["HOST_TOKENS"]) == {digest:"host-one"}
    enrollment = json.loads(state()["kv"]["expected/host-one"])
    assert enrollment["enabled"] is True and enrollment["at"].endswith("Z")
    assert enrollment["enrollment"] == digest

    marker("fail-revoke-once")
    run("remove-host", "host-one", ok=False)
    assert hosts() == {"host-one":digest} and (deploy / ".tattle-pending.json").exists()
    run("remove-host", "host-one")
    assert hosts() == {} and json.loads(state()["secrets"]["HOST_TOKENS"]) == {} and state()["kv"] == {}
    run("remove-host", "host-one")
    assert hosts() == {} and state()["kv"] == {}

    marker("fail-add-once")
    run("add-host", "failed-publication", ok=False)
    assert hosts() == {} and json.loads(state()["secrets"]["HOST_TOKENS"]) == {} and state()["kv"] == {}
    marker("fail-enroll-once")
    run("add-host", "failed-host", ok=False)
    assert hosts() == {} and json.loads(state()["secrets"]["HOST_TOKENS"]) == {} and state()["kv"] == {}
    assert not (deploy / ".tattle-pending.json").exists()
    # Both enrollment and rollback can fail. A normal retry must finish rollback.
    marker("fail-enroll-once"); marker("fail-revoke-once")
    run("add-host", "retry-host", ok=False)
    assert hosts() == {} and (deploy / ".tattle-pending.json").exists()
    run("add-host", "retry-host")
    assert list(hosts()) == ["retry-host"]
    marker("fail-cleanup-once")
    run("remove-host", "retry-host", ok=False)
    assert json.loads(state()["secrets"]["HOST_TOKENS"]) == {} and (deploy / ".tattle-pending.json").exists()
    run("remove-host", "retry-host")
    assert hosts() == {} and state()["kv"] == {}

    # Simulate termination after local add commit but before journal removal.
    crash_digest = "a" * 64
    (deploy / "hosts.json").write_text(json.dumps({"crash-host":crash_digest}))
    (deploy / ".tattle-pending.json").write_text(json.dumps({"op":"add", "name":"crash-host", "old":{}, "target":{"crash-host":crash_digest}, "at":"2026-10-01T00:00:00Z"}))
    current=state(); current["secrets"]["HOST_TOKENS"]=json.dumps({crash_digest:"crash-host"}); current["kv"]["expected/crash-host"]=json.dumps({"at":"2026-10-01T00:00:00Z", "enabled":True, "enrollment":crash_digest}); remote.write_text(json.dumps(current))
    run("remove-host", "crash-host")
    assert hosts() == {} and json.loads(state()["secrets"]["HOST_TOKENS"]) == {} and state()["kv"] == {}

    # An invalid private config must fail locally before deploy or pending
    # transaction recovery has any remote effect. Parse quoted/dotted TOML keys
    # and multiline arrays rather than relying on textual snippets.
    config_path = deploy / "wrangler.toml"
    invalid_configs = [
        'name = "test"\nmain = "src/index.js"\n',
        valid_config.replace('class_name = "HostGate"', 'class_name = "WrongGate"'),
        valid_config.replace('class_name = "HostGate"', 'class_name = "HostGate"\nscript_name = "other-worker"'),
        valid_config.replace('new_sqlite_classes', 'new_classes'),
        valid_config + '\n[[migrations]]\ntag = "delete"\ndeleted_classes = ["HostGate"]\n',
        valid_config + '\n[[migrations]]\ntag = "rename"\nrenamed_classes = [{from = "HostGate", to = "OtherGate"}]\n',
        valid_config + '\n[[migrations]]\ntag = "conflict"\nnew_classes = ["HostGate"]\n',
        valid_config.replace('new_sqlite_classes = ["HostGate"]', 'new_sqlite_classes = ["HostGate"]\nnew_classes = ["HostGate"]'),
        valid_config + '\n[[durable_objects.bindings]]\nname = "HOST_GATE"\nclass_name = "HostGate"\n',
        valid_config + '\n[[migrations]]\ntag = "v1-host-gate"\nnew_sqlite_classes = ["OtherGate"]\n',
        valid_config.replace('main = "src/index.js"', ''),
        'not valid TOML [',
    ]
    pending = deploy / ".tattle-pending.json"
    pending.write_text(json.dumps({"op":"remove", "name":"pending-host", "old":{}, "target":{}, "at":"2026-10-01T00:00:00Z"}))
    for invalid_config in invalid_configs:
        config_path.write_text(invalid_config)
        rejects_without_remote_change("deploy")
        rejected = run("deploy", ok=False)
        assert "deploy preflight failed" in rejected.stderr
        assert 'new_sqlite_classes = ["HostGate"]' in rejected.stderr
        assert config_path.read_text() == invalid_config, "preflight edited private config"
    config_path.write_text(valid_config)
    marker("fail-dry-run-once")
    before_remote, before_hosts, before_pending, before_calls = remote.read_bytes(), (deploy / "hosts.json").read_bytes(), pending.read_bytes(), len(calls())
    rejected = run("deploy", ok=False)
    assert "Wrangler deploy preflight failed" in rejected.stderr
    assert remote.read_bytes() == before_remote and (deploy / "hosts.json").read_bytes() == before_hosts and pending.read_bytes() == before_pending
    assert [call["argv"][2:] for call in calls()[before_calls:]] == [["deploy", "--dry-run"]]
    before_calls = len(calls())
    run("deploy")
    assert calls()[before_calls]["argv"][2:] == ["deploy", "--dry-run"]
    assert not pending.exists(), "valid preflight must allow pending recovery"
    alternate_config = valid_config.replace('[[durable_objects.bindings]]', '[["durable_objects"."bindings"]]').replace('new_sqlite_classes = ["HostGate"]', 'new_sqlite_classes = [\n  "HostGate", # SQLite admission gate\n]')
    config_path.write_text(alternate_config)
    run("deploy")
    config_path.write_text(valid_config)

    run("deploy")
    assert all(k not in state()["secrets"] for k in ("HEARTBEAT_URL", "CANARY_EMAIL", "NTFY_TOKEN"))
    deletions = [c["argv"][-1] for c in calls() if c["tool"] == "wrangler" and "delete" in c["argv"] and "secret" in c["argv"]]
    assert deletions == ["HEARTBEAT_URL","CANARY_EMAIL","NTFY_TOKEN"]
    run("deploy")  # absent optional secrets are harmless, with no blind delete.
    assert len([c for c in calls() if "secret" in c["argv"] and "delete" in c["argv"]]) == 3
    marker("fail-list-once"); run("deploy", ok=False)
    current = state(); current["secrets"]["HEARTBEAT_URL"]="old"; remote.write_text(json.dumps(current))
    marker("fail-delete-once"); run("deploy", ok=False)
    assert state()["secrets"]["HEARTBEAT_URL"] == "old"
    with secrets.open("a") as f: f.write("HEARTBEAT_URL=https://heartbeat.invalid/new\nCANARY_EMAIL=canary@example.invalid\nNTFY_TOKEN=ntfy-synthetic\n")
    run("deploy")
    assert state()["secrets"]["HEARTBEAT_URL"] == "https://heartbeat.invalid/new"
    assert state()["secrets"]["CANARY_EMAIL"] == "canary@example.invalid"
    assert state()["secrets"]["NTFY_TOKEN"] == "ntfy-synthetic"

    # Fresh init emits valid trusted shell configuration and a private hash map.
    init_deploy = work / "init-deploy"; init_deploy.mkdir(mode=0o700)
    init_secrets = work / "init-config" / "secrets.env"
    run("init", extra={"TATTLE_DEPLOY":str(init_deploy), "TATTLE_SECRETS":str(init_secrets)})
    assert json.loads((init_deploy / "hosts.json").read_text()) == {}
    assert stat.S_IMODE(init_secrets.stat().st_mode) == 0o600
    subprocess.run(["sh", "-c", '. "$1"; test -n "$READ_TOKEN" && test -n "$CANARY_KEY"', "sh", str(init_secrets)], check=True, stdout=subprocess.DEVNULL)

    # Ownership/mode and symlink checks run before sourcing trusted config.
    secrets.chmod(0o644); run("status"); assert stat.S_IMODE(secrets.stat().st_mode) == 0o600
    link = work / "linked-secrets"; link.symlink_to(secrets)
    run("status", ok=False, extra={"TATTLE_SECRETS":str(link)})
    assert stat.S_IMODE((deploy / "hosts.json").stat().st_mode) == 0o600
    print("operator CLI hardening: all offline checks passed")
PY
