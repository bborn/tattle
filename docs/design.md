# tattle: design

Security monitoring for one person who runs a handful of laptops and servers and
has no SOC. Free to run. Assumes every machine will eventually be compromised, and
optimises for two things: knowing quickly, and limiting what one compromised
machine can reach.

## Principles

1. **Detection lives off the box.** Anything a compromised machine can edit, it
   can lie about. Reports leave the machine the moment they are made, into storage
   the machine can write to but never read, overwrite or delete.
2. **Silence is a signal.** A machine that stops reporting raises an alert. The
   check runs somewhere other than your own machines.
3. **Canaries before scanners.** A fake credential that nobody legitimate uses
   gives an alert with almost no false positives. Scanners find drift; canaries
   find intruders.
4. **No AI on the monitored machine, and no power for the AI that reads.**
   Collection is plain shell. The model that summarises reports gets read-only file
   access to copies of them, with no shell, network or credentials, because every
   byte it reads may have been written by an attacker.
5. **Free.** Cloudflare free tier, ntfy.sh, canarytokens.org, open-source
   collectors.

## Components

```
 machine (macOS / Linux)                Cloudflare (free)              you
 ┌──────────────────────┐   POST     ┌──────────────────────┐
 │ collector (launchd / │──────────▶ │ Worker: /ingest       │
 │ systemd timer, daily)│ per-host   │  write-once to R2     │
 └──────────────────────┘  token     │  diff vs last report  │──▶ ntfy ──▶ phone
                                     │ cron: missed check-in │──▶ ntfy
 canarytokens.org ── trip ─────────▶ │ /canary               │──▶ ntfy (max priority)
                                     └──────────┬───────────┘
                                                │ read-only token
                                     ┌──────────▼───────────┐
                                     │ weekly digest        │
                                     │ (planned: LLM with   │
                                     │  read-only tools)    │
                                     └──────────────────────┘
```

### collector

One POSIX shell script for macOS and Linux (`collector/tattle-collect`), run daily
as root. Uses base-system tools; optional Tailscale, Docker and weekly Lynis tools are
used only when their resolved executable and full path meet the collector trust
policy. `tattle-collect --print` shows the report instead of sending it.

| section | macOS | Linux |
|---|---|---|
| identity | hostname, OS version, serial | hostname, machine-id, OS, kernel |
| accounts | admin group members, users with UID ≥ 500 | sudo/wheel/docker/lxd/libvirt members, UID 0 and ≥ 1000 accounts |
| ssh | authorized_keys fingerprints, keys without a passphrase, remote login | same, plus the effective sshd settings that matter |
| listening | listening sockets with process | same |
| persistence | LaunchAgents/Daemons (path + hash), cron metadata/digest, profiles, sudoers hash | enabled units, unit file hashes, cron, ld.so.preload, rc.local, sudoers |
| posture | FileVault, SIP, Gatekeeper, firewall, update settings, auto-login, guest, screen sharing | ufw/nftables, unattended upgrades |
| updates | recommended updates, last successful update | pending and security updates, reboot required |
| exposure | app firewall allow list, `tailscale serve`/`funnel` | `tailscale serve`/`funnel` |
| containers | | running containers and published ports |
| credentials | path and mode of known credential files (never contents) | same |
| packages | /Applications, brew | package count and hash |
| tailscale | self and peer names and OS | same |
| lynis | | hardening index and warnings (Sundays) |

macOS cron collection sends a hex-encoded account name, active-line count and
SHA-256 digest of normalized active lines, replacing raw commands and environment
assignments that could contain secrets. The count and digest share one stream;
command text is not retained in scratch files.

The collector avoids credential contents, but reports are sensitive inventory and
command output may still contain sensitive data. Path evidence uses `path-hex:`
followed by the complete hexadecimal path bytes, avoiding newline/delimiter
ambiguity. JSON preserves non-ASCII bytes as U+00xx escapes. Each section is
limited to 16 KiB of raw output and 30 seconds (180 seconds for Lynis), with
failure, timeout or truncation evidence recorded. Reports are gzipped and posted
to `/ingest`; `--print` retains the same bounded collection without uploading.

The installer and collector set a system-only PATH. Optional tools are resolved
component by component, including symlink targets, and checked for root ownership,
unsafe mode bits and ACL grants before execution. An unavailable or untrusted
optional tool is skipped. The installer validates privileged destination ancestry,
refuses symlinks and unsafe existing ownership/modes/ACLs, and publishes code,
the mode-600 environment file and scheduler files by atomic rename from unique
temporary files in trusted destination directories. macOS uses canonical
`/private/etc` and `/private/var/log` paths. This preserves launchd, systemd and
cron scheduling, first-report upload and optional canary planting. The temporary
canary script is owned by the planting user and mode 0600 before execution, then
removed.

### worker (Cloudflare Worker + R2 + KV + Durable Objects)

- `POST /ingest` uses `Authorization: Bearer <host token>`. `HOST_TOKENS` maps
  SHA-256 token hashes to host names. The server supplies the archived host and
  receipt timestamp, regardless of client-supplied values.
- `HOST_GATE` is required, with the binding and SQLite migration from
  `worker/wrangler.toml.example`. One host-named Durable Object serializes report
  and canary requests across enrollments and await points; KV is a query/silence
  view, not the admission authority. Missing binding returns 503.
- A valid report gets a stable random archive key
  `reports/<host>/<ISO timestamp>-<UUID>.json`. Its payload and pending state are
  stored durably before R2 creation. Conditional create and the same key recover
  retries without overwriting or deleting archives. Two-minute recovery leases
  and a six-attempt hourly budget bound retries. A different report cannot replace
  pending work. One successful report per hour is allowed; dependency failures
  return 503 for retry rather than acknowledging lost work.
- The host coordinator durably stores the active token hash. Activation of a new
  hash atomically resets enrollment-local report, retry and canary state and
  payload chunks, and permanently tombstones the previous hash as
  `retired/<hash>`. Immutable archives and prior tombstones remain. Delayed
  old-token requests are rejected after new activation, even if an old Worker
  instance still has the previous token map. KV seen/baseline records are tagged
  with the token hash. Untagged legacy
  KV state can seed an existing enrollment only when no enabled expected record
  exists; a completed report writes tagged state. A fresh expected enrollment
  ignores legacy state and records tagged for another token.
- The previous archive supplies the diff baseline. New admin/sudo/UID 0 accounts,
  SSH keys, persistence items, non-loopback listeners and posture changes raise
  alerts. Notification progress is persisted, though a crash between a successful
  notification and its receipt can still duplicate an alert.
- The hourly sweep checks currently enrolled hosts through their host coordinator,
  up to 500 hosts per invocation, continuing through the fleet with a persistent
  cursor. Small fleets are checked every hour; with a stable fleet of N hosts,
  a complete pass takes `ceil(N / 500)` hourly runs (20 at the 10,000-host maximum).
  Failed hosts do not prevent cursor progress. `expected/<host>` starts the silence clock at enrollment, so a
  host that never reports alerts after `STALE_HOURS` (default 36), with daily
  reminders. The enrollment-tagged expected marker persists after reports; ingest
  never clears it. Sweeps write enrollment-specific reminder receipts to
  `silence/<host>/<hash>`, without rewriting shared expected/seen records, so a
  paused old sweep cannot replace current enrollment state. A reporting host
  that was marked stale raises a recovery alert. Host failures do not stop other
  hosts' checks. `HEARTBEAT_URL` is pinged even when a sweep operation fails;
  monitor invocation failures as well as the outside heartbeat.
- On upgrade, a configured host with neither seen nor expected state receives a
  fresh grace timestamp durably recorded in its coordinator, then an immutable
  `bootstrap/<host>/<token-hash>` fallback marker. Retries retain that timestamp.
  Explicit enrollment markers take precedence, and old initialization cannot
  overwrite a replacement enrollment. Existing reporting hosts retain their
  baseline and last-report time; disabled or corrupt explicit state is not
  silently rewritten. Backfill occurs as the bounded sweep reaches each host.
- `POST /canary` accepts bearer or query-key authentication before opening the
  body, with a 64 KiB decoded-byte cap. New canaries use an HMAC callback
  key bound to the host and active token hash. Revocation invalidates that key;
  re-enrolling the same host name with a new token does not reactivate it. The global
  `CANARY_KEY` remains accepted for existing canaries and operator test alerts.
- `GET /canaries.sh` requires a host token. The host gate caches one successful
  planting script per enrollment, with two-minute leases and at most six
  provisioning attempts per hour. An optional single `user` query parameter
  defaults to `user` and must match `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`. The first
  successful provisioning binds its memo to that initial host/user; later valid
  query changes reuse the cached script and memo. Provider HTTP status, error
  flags, required credential fields, region
  and DNS hostname syntax are checked before generating shell text. Failed
  attempts can still mint partial provider tokens before a retry.
- `GET /install.sh` and `/tattle-collect` serve the deployed text assets.

#### Report input

The decoded report body is capped at 2 MiB, including gzip expansion. Unsupported
encodings, malformed gzip, invalid JSON and schema failures are rejected before
storage changes. A report is an object with a positive integer `version` up to
10000, a bounded simple `os` identifier, a parseable timestamp `collectedAt`, and
`sections`: 1–64 named string values. Section names match
`[a-z][a-z0-9_]{0,63}` and each section is at most 2 MiB in UTF-8, within the total body cap. Prototype-related
names and unknown top-level fields are rejected. Optional `host` and `receivedAt`
fields must validate but are discarded before admission; archived values are
server-controlled. These checks validate structure, not the truth of a report
from a compromised machine.

#### Read API

All read routes require `Authorization: Bearer <READ_TOKEN>`:

| route | response and parameters |
|---|---|
| `GET /hosts` | Original complete `{ "hosts": { "name": { "at": "…", "staleAlertedAt": null } } }`; includes seen hosts and enrolled hosts awaiting their first report |
| `GET /reports` | Original complete `{ "keys": ["reports/…json"] }`; optional `host` and timestamp `since` filters |
| `GET /report?key=…` | one archived JSON report; accepts only report-key paths |

Default complete responses are bounded to 200 scanned host-state keys, 10,000
scanned report keys, 100 backend listing pages, and 4 MiB of serialized JSON. Exceeding a bound returns
`413` with instructions to use pagination; no partial successful listing is
returned. Host-state key counts include enrollment and bootstrap markers, not
just distinct machines.

Add `pagination=1` to opt into responses with a `cursor`. In that mode,
`/hosts` and `/reports` accept `limit` from 1 to 500 (default 100; host pages are
internally capped at 200 markers) and an opaque
`cursor` (up to 8192 characters for hosts, 4096 for reports). Pass each non-null
cursor to the next request, preserving `pagination=1` and filters. Host pagination visits seen state,
explicit enrollments, then bootstrap markers; pending records add `"status": "awaiting-first-report"`,
with `at` set to enrollment time. A host already seen is omitted from the pending
phase. Any empty page with a cursor still needs another request. `since` filters the current R2 listing page, so an empty
`keys` array with a non-null cursor still needs another request. `tattle status`
follows pages transparently, labels pending hosts as awaiting their first report,
rejects repeated cursors and stops with an error
if more than 1000 pages are required. Read tokens cannot enroll or revoke hosts.

### operator state

Run `npm ci` in `worker/` to install the lockfile-pinned local Wrangler. The CLI
keeps the private `wrangler.toml` in `TATTLE_DEPLOY`, copying it only to a unique
mode-600 temporary config beside the Worker source for path resolution, with
cleanup on exit. It never replaces a shared source-tree config. Protect
`TATTLE_SECRETS`: it is trusted shell configuration, checked before sourcing.

Deploy requires Python 3.11 or newer for TOML parsing. Before remote recovery or
deployment writes, it validates the local `HOST_GATE -> HostGate` binding and
SQLite migration history, then runs Wrangler's `deploy --dry-run` against the
configured entrypoint. Errors include an actionable configuration example; the
private configuration is not rewritten. Collector hosts require no Python.

`add-host` and `remove-host` take a deployment lock and use an atomically written,
fsynced recovery journal. Add publishes the target token map and
`expected/<host>` (including its enrollment token hash) before committing the
local host list and revealing a token.
An interrupted add rolls back/revokes before a fresh enrollment; an interrupted
remove retries revocation and expected/seen/baseline cleanup. Removal preserves
archives. Recovery is idempotent across retries; Cloudflare secret publication,
KV writes and local files are not one distributed atomic transaction. Prefer the
printed `--prompt-token` install command, which reads from `/dev/tty` with echo
disabled. Positional tokens remain compatible; a saved installer also accepts
`--token-stdin`.

### weekly digest (planned)

Copy the week's reports into a scratch directory on a machine that is not one of
your most privileged ones, and run a model with read-only file tools over it to
write a short digest: what changed, what looks wrong, what to fix first. Output is
a summary for a human, never an action. Every byte in those reports may have been
written by an attacker, so the model gets no shell, network or credentials.

### canaries

At install, the worker mints canarytokens.org tokens for that machine and plants
them in the home directory of the person who uses it (root on a server):

- a fake AWS profile appended to `~/.aws/credentials` under `[backup-admin]`
  (existing profiles are left alone)
- `~/Documents/prod-secrets.env` with a second fake AWS key
- a `Host db-backup-prod` entry in `~/.ssh/config` whose hostname is a DNS token

Each token's memo records the initial host/user and file, so an alert says exactly which
machine and which file was touched. Planting is idempotent; set
`TATTLE_NO_CANARIES=1` to skip it. After re-enrollment, installer flag
`--refresh-canaries` passes `--refresh` to the generated script. It validates
all target plans before replacement, preserves unrelated bytes, creates private
backups, and atomically replaces recognized Tattle-owned blocks. Newly planted
blocks have explicit begin/end markers. Exact legacy marked AWS/SSH blocks can
be refreshed; an unmarked old `prod-secrets.env` cannot establish ownership and
requires manual inspection and removal from that path before retrying. Links,
ambiguous blocks, and conflicting user-owned sections are rejected. Refresh
uses the cached enrollment's canaries and does not bypass provisioning budgets.

## Hardening baseline (documented, not automated)

Per machine type, the short list that most reduces blast radius: full-disk
encryption, auto-updates, non-admin daily accounts, SSH only over Tailscale,
no long-lived cloud keys on laptops, one credential per machine, backups that the
backed-up machine cannot delete.

## Repo split

- `tattle` (this repo, public): engine. No hostnames, tokens or findings.
- a private deployment repo per operator: host list, token hashes, ntfy topic,
  findings and audit notes.
