# Hardening checklist

The short list that most reduces blast radius for a small fleet. Each item came
from a real audit. tattle reports on most of these but does not change them.

## Monitoring must not share credentials with what it monitors

- Deploy the tattle worker in a Cloudflare account used for nothing else, with
  credentials kept off every monitored machine. A laptop logged into the same
  account with `wrangler` can delete the worker and silence every alert.
- Add an outside dead-man's switch (for example a free healthchecks.io check)
  and set it as `HEARTBEAT_URL`. If the worker is deleted, that check alerts.
- Run the weekly analyzer somewhere that is not your most-privileged machine.

## Deployment controls the code cannot establish

- Keep deployment credentials, the read token and global canary key off monitored
  machines. Protect the operator's secrets file and private deployment directory;
  the secrets file is executable shell configuration. Use `npm ci` and the pinned
  `worker/node_modules/.bin/wrangler`, then deploy through `bin/tattle` so private
  configuration is copied only into a unique, cleaned temporary config.
- Keep the `HOST_GATE` Durable Object binding and migration in your private
  `wrangler.toml`. The gate supplies strict per-host admission, durable report
  recovery and bounded canary enrollment through one host-named coordinator. It
  durably tracks the active token hash, atomically resets local state on rotation
  and permanently retires old hashes. KV alone cannot supply serialization.
- Configure and verify the R2 retention lock and lifecycle independently. Worker
  code uses stable keys and conditional create and has no archive-delete route;
  an account owner or stolen deployment credential has broader authority unless
  storage retention rules constrain it.
- Protect DNS, Cloudflare account access and HTTPS deployment authority. Installer
  path checks do not authenticate the intent of code served by a compromised
  deployment. Optional signed releases and independently verified provenance add
  another distribution control; this repository does not supply that verification.
- Prefer `--prompt-token` for installation. Legacy positional tokens can be saved
  in shell history and sudo logs. A host token can submit that host's reports and
  request its bounded canary planting script; it cannot retrieve archives. New
  canary callbacks are bound to the host and active token hash; revocation or
  re-enrollment invalidates the old callback key. Legacy global-key callbacks still
  work, so protect the global key and plan migration before rotating it.

## Collector and enrollment safeguards

The installer validates root ownership, modes, ACLs and nonsymlink destination
ancestry before privileged writes, uses a system-only PATH, and atomically
publishes unique temporary files. It refuses unsafe existing paths rather than
repairing them into trusted paths. The collector checks resolved optional-tool
paths, bounds each section's time and output, and encodes path evidence. Review
reported timeouts/truncation: bounded collection can omit evidence, and root can
still forge collection output.

Enrollment creates persistent, token-hash-tagged `expected/<host>` state so a
machine that never reports still alerts after the grace period. Ingest retains
that marker. Sweeps write `silence/<host>/<hash>` receipts without rewriting
shared expected/seen state. Add/remove operations use a lock and recovery
journal; retry a failed operation to finish rollback or cleanup. Removal revokes
the host token and clears expected/seen/baseline views while retaining archived
reports. Report ingestion, canary planting, status, report retrieval, alerting and
silence checks remain available alongside macOS/Linux collection, `--print`,
launchd, systemd and cron scheduling. See [the design](design.md) for exact request
limits, pagination and recovery behavior.

Upgrades automatically initialize a fresh silence grace period for legacy hosts
with no seen or enrollment state, using immutable token-scoped bootstrap markers
instead of changing existing baselines. The sweep covers 500 hosts per run.
Original complete reader envelopes remain the default within resource bounds;
larger readers opt into `pagination=1` and follow cursors. Deploy validates TOML
and bundles locally before remote recovery or deployment writes. The operator
needs Python 3.11 or newer for preflight.

Use installer `--refresh-canaries` after re-enrollment to replace recognized
Tattle blocks while preserving other profiles and entries. Replaced files have
private backups. Refresh fails closed on unsafe links and ambiguous ownership,
including legacy unmarked `prod-secrets.env`: inspect and move only the known old
canary aside before retrying. Ordinary installs remain idempotent.

## Laptops

- **FileVault on.** `fdesetup status` is the source of truth. Apple-silicon
  "encrypted at rest" is not tied to your password and does not protect a stolen
  machine.
- **Updates actually installing.** A failed update can sit unnoticed for years.
  Check that the installed version is not behind an available one.
- **Passphrases on SSH keys**, or keys in the Secure Enclave or 1Password's SSH
  agent. A key file with no passphrase is a password written on the disk.
- **No long-lived cloud admin keys on disk.** Use SSO / short sessions. An old IAM
  user key with IAMFullAccess lets whoever holds it mint their own admin.
- **Credential files mode 600.**
- **Nothing served to the tailnet without auth.** `tailscale serve` exposes a port
  to every device on the tailnet, including servers that may be compromised.
- **App firewall:** review the allowed-incoming list (it can quietly include `nc`,
  `node`, or a tunnel binary).

## Servers

- SSH only over Tailscale. No public port 22.
- `docker`, `lxd` and `libvirt` group membership is root without a password. Treat
  them as admin groups.
- Docker-published ports bypass ufw/firewalld. Bind to 127.0.0.1 or the tailnet
  IP, never 0.0.0.0, unless the port is meant to be public.
- Behind Cloudflare: allow 80/443 only from Cloudflare's IP ranges, or anyone who
  finds the origin IP bypasses the WAF. Test each proxied hostname with
  `curl --resolve host:443:<origin ip> https://host/`. Any 2xx or 3xx means the
  origin is reachable directly.
- A GitHub self-hosted runner on a production box means anyone who can push a
  workflow can run code there. Restrict runner groups to specific workflows and
  make runners ephemeral.
- Servers don't need CUPS (port 631), SSH agent or TCP forwarding, or a Claude or
  other AI login (`~/.claude/.credentials.json`). If auth failures are high and
  nothing like fail2ban is running, move SSH behind Tailscale.
- No plaintext passwords in `~/.ssh/config` comments.
- App secret files (`.env`, `application.yml`, platform env files) mode 600, owned
  by the app user. A 644 `.env` can be read by every account on the box.
- No database dumps, backup exports or one-off probe scripts left in app users'
  home directories. They are usually full of customer data.
- Reboot after kernel updates. `/var/run/reboot-required` that is weeks old means
  the running kernel is unpatched however current the packages look.
- On home or office machines that also run Tailscale, bind sshd, dev servers and
  dashboards to the tailnet address or 127.0.0.1, not 0.0.0.0, so the LAN can't
  reach them.
- Machines running AI agents should not hold production database credentials,
  even read-only ones. One prompt injection or one bad `npx`/`uvx` package reads
  all of it. Give agents a masked replica.

## Cloud accounts

- No admin or IAMFullAccess policy on application keys. Delete keys older than a
  year or unused for a year, and require MFA for every console user.
- CloudTrail that nobody reads is not monitoring. Send it somewhere that alerts.
- Lambda Function URLs with `AuthType NONE` are public endpoints. Check that each
  one is meant to be.

## Secrets and images

- Each environment gets its own secrets. Compare SHA-256 prefixes (never the
  values) of keys like `SECRET_KEY_BASE`, `RAILS_MASTER_KEY` and encryption keys
  across production, staging and demo. If they match, a staging leak is a
  production leak.
- Images, snapshots and templates inherit the trust of the machine they were
  built from. After a compromise, list everything built from or copying files
  from that machine and rebuild it.

## Trust between machines

- Map which machine's key logs into which (tattle collects `own-key` and
  `authorized_keys` fingerprints for this). Trust should flow from your laptop to
  servers, never from a server back to your laptop.
- Tailscale: tag servers, and write ACLs so tagged servers cannot reach personal
  devices. Turn on Tailnet Lock. Remove nodes offline for more than 14 days.

## Backups

- The machine being backed up must not be able to delete its backups. Use an
  append-only restic server, or an object-lock bucket with a write-only token, and
  run `forget --prune` from somewhere else.

## Accounts

- Require 2FA in every GitHub org you administer (check the member list first:
  members without 2FA are removed).
- Fine-grained, expiring tokens. A `gh` token with `workflow` scope can rewrite CI
  in every repo it reaches.
- Sweep public DNS for forgotten hosts: zone files, certificate transparency
  (crt.sh often returns 502s, and certspotter works as a fallback) and a list of
  common labels. Flag records that point at IPs you no longer own, CNAMEs to
  hosted services whose target no longer exists (takeover candidates on Heroku,
  Fly, Shopify, hosted dashboards and the like), registrar parking records that
  point at third-party domains, and secondary domains with no DMARC or
  `sp=none`.
- A known_hosts host-key mismatch for an address you own is worth chasing. It is
  often the first sign that the IP was released and now belongs to someone else.
- Fetch every owned hostname and look for takeover fingerprints: "Site not
  found", Heroku "Application Error" or "no such app", S3 `NoSuchBucket`.
- A required status check that anyone with write access can post (a custom
  "signoff" status, say) is not branch protection.
- Set the default workflow token permission to read, and remove collaborators
  with no activity.
- Review GitHub Apps that can write contents and workflows on every repo, and
  pin third-party Actions to a commit SHA rather than a branch or tag.
