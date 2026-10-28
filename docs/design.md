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
5. **Free.** Cloudflare free tier, canarytokens.org, open-source
   collectors.

## Components

```
 machine (macOS / Linux)                Cloudflare (free)              you
 ┌──────────────────────┐   POST     ┌──────────────────────┐
 │ collector (launchd / │──────────▶ │ Worker: /ingest       │
 │ systemd timer, daily)│ per-host   │  write-once to R2     │
 └──────────────────────┘  token     │  diff vs last report  │──▶ email
                                     │ cron: missed check-in │──▶ email
 canarytokens.org ── trip ─────────▶ │ /canary               │──▶ email
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
as root. No dependencies beyond the base system; `lynis` is used weekly when
present. `tattle-collect --print` shows the report instead of sending it.

| section | macOS | Linux |
|---|---|---|
| identity | hostname, OS version, serial | hostname, machine-id, OS, kernel |
| accounts | admin group members, users with UID ≥ 500 | sudo/wheel/docker/lxd/libvirt members, UID 0 and ≥ 1000 accounts |
| ssh | authorized_keys fingerprints, keys without a passphrase, remote login | same, plus the effective sshd settings that matter |
| listening | listening sockets with process | same |
| persistence | LaunchAgents/Daemons (path + hash), cron, profiles, sudoers hash | enabled units, unit file hashes, cron, ld.so.preload, rc.local, sudoers |
| posture | FileVault, SIP, Gatekeeper, firewall, update settings, auto-login, guest, screen sharing | ufw/nftables, unattended upgrades |
| updates | recommended updates, last successful update | pending and security updates, reboot required |
| exposure | app firewall allow list, `tailscale serve`/`funnel` | `tailscale serve`/`funnel` |
| containers | | running containers and published ports |
| credentials | path and mode of known credential files (never contents) | same |
| packages | /Applications, brew | package count and hash |
| tailscale | self and peer names and OS | same |
| lynis | | hardening index and warnings (Sundays) |

The collector never sends file contents beyond what is listed, and never sends
secrets. The ingest token is the only credential on the machine. Reports are
gzipped and posted to `/ingest`.

### worker (Cloudflare Worker + R2 + KV)

- `POST /ingest` with `Authorization: Bearer <host token>`. Tokens are stored as
  SHA-256 hashes mapped to a host name, so a token can only write as its own host.
- Writes `reports/<host>/<ISO timestamp>-<random>.json` and never overwrites or
  deletes. An R2 bucket lock (90 days) enforces this at the storage layer.
- Compares the report with the host's previous one (kept in KV) and alerts on:
  new admin/sudo/UID 0 accounts, new SSH keys, new persistence items, a process
  newly listening on a non-loopback address, and any posture change. Everything
  else stays in the stored reports.
- Hourly cron: a host silent for longer than `STALE_HOURS` (default 36) raises an
  alert, then one reminder a day until it reports again. If `HEARTBEAT_URL` is
  set, each cron run pings it, so an outside dead-man's switch notices if the
  worker itself is deleted.
- `POST /canary?key=…` receives canarytokens.org webhooks and alerts by email
  (and by ntfy push, if that is set up). ntfy is optional; without email it
  takes every alert. An alert counts as delivered if any channel gets it
  through. If every channel fails, the request fails too, so the sender retries.
- `GET /install.sh`, `GET /tattle-collect`: the installer and collector, served
  from this repo so every machine runs the version you deployed.
- `GET /canaries.sh` (host token): mints canaries for that host and returns a
  script that plants them.
- `GET /hosts`, `/reports`, `/report` (read token): last-seen times and stored
  reports, for `tattle status` and the digest.

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

Each token's memo records host, user and file, so an alert says exactly which
machine and which file was touched. Planting is idempotent; set
`TATTLE_NO_CANARIES=1` to skip it.

## Hardening baseline (documented, not automated)

Per machine type, the short list that most reduces blast radius: full-disk
encryption, auto-updates, non-admin daily accounts, SSH only over Tailscale,
no long-lived cloud keys on laptops, one credential per machine, backups that the
backed-up machine cannot delete.

## Repo split

- `tattle` (this repo, public): engine. No hostnames, tokens or findings.
- a private deployment repo per operator: host list, token hashes,
  findings and audit notes.
