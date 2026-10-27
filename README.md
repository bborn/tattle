# tattle

Free security monitoring for one person who looks after a handful of laptops and
servers (your own, your family's, a small company's) and has no security team.

tattle assumes every machine will be compromised at some point. It doesn't try to
prevent that. It tries to make sure you hear about it quickly, from somewhere the
attacker can't reach, and it points out what one compromised machine could get to.

- **Daily snapshot.** A small shell script runs as root on each Mac or Linux box
  and records accounts, SSH keys, listening ports, persistence (launch agents,
  systemd units, cron), security settings, pending updates, credential file
  permissions and Tailscale exposure.
- **Off-box diff.** The snapshot goes straight to a Cloudflare Worker you own,
  into an R2 bucket the machine can write to but can't read, change or delete.
  The Worker compares it with the previous day's and sends a phone alert through
  ntfy when something security-relevant changes: a new admin, a new SSH key, a
  new launch daemon, a process newly open to the network, FileVault or the
  firewall turned off.
- **Silence alerts.** If a machine stops reporting for 36 hours, you get an alert.
  An attacker who disables the collector can't make that alert go away.
- **Canaries.** At install, tattle plants fake AWS keys and a fake SSH host in
  each user's home directory, using free canarytokens.org tokens. Nobody
  legitimate ever uses them, so if one is used you get a max-priority alert naming
  the machine and the file, usually within seconds.

Everything runs on free tiers: Cloudflare Workers, R2 and KV, ntfy.sh and
canarytokens.org. There is no agent to install beyond one POSIX shell script, and
no AI runs on the monitored machines.

See [docs/design.md](docs/design.md) for how it works and why, and
[docs/hardening.md](docs/hardening.md) for the short list of fixes that most
reduce blast radius. Most of them came up in real audits of real machines.

## What you need

- A Cloudflare account. **Use a new one that you use for nothing else**, and keep
  its credentials off every machine you monitor. Anyone with a `wrangler` login to
  the monitoring account can delete the Worker and silence every alert.
- The [ntfy](https://ntfy.sh) app on your phone.
- Node.js and npm (for the pinned local Wrangler), `python3` and `curl` on the
  machine you operate from.
- Optional: a free [healthchecks.io](https://healthchecks.io) check, to alert you
  if the Worker itself stops running.

## Setup

tattle keeps two kinds of state apart. This repo is the engine. Your deployment
(Worker config and host list) lives in a private directory of your own, ideally a
private git repo, and your secrets live in a mode-600 file outside both.

```sh
git clone https://github.com/bborn/tattle && cd tattle
export TATTLE_DEPLOY=~/tattle-deploy      # your private deployment directory
mkdir -p "$TATTLE_DEPLOY"
(cd worker && npm ci)                  # installs the lockfile-pinned Wrangler

# 1. Cloudflare resources (logged in to the monitoring account)
worker/node_modules/.bin/wrangler login
worker/node_modules/.bin/wrangler r2 bucket create tattle-reports
worker/node_modules/.bin/wrangler r2 bucket lock add tattle-reports keep-90d "" --retention-days 90
worker/node_modules/.bin/wrangler r2 bucket lifecycle add tattle-reports expire-1y "" --expire-days 365
worker/node_modules/.bin/wrangler kv namespace create STATE    # note the id it prints

# 2. Worker config
cp worker/wrangler.toml.example "$TATTLE_DEPLOY/wrangler.toml"
# edit it: put the KV namespace id in; keep HOST_GATE and its migration

# 3. Secrets, then deploy
bin/tattle init        # writes ~/.config/tattle/secrets.env (read token, canary key, ntfy topic)
bin/tattle deploy      # deploys the Worker and HOST_GATE migration; prints its URL
# put that URL in TATTLE_URL in ~/.config/tattle/secrets.env
```

The CLI uses `worker/node_modules/.bin/wrangler`. It copies your private config
into a unique mode-600 temporary file beside the Worker source for each command
and cleans it up on exit; it does not create a shared `worker/wrangler.toml`.
The `HOST_GATE` Durable Object binding and migration in the example are required
for report admission and canary provisioning.

Subscribe to the `NTFY_URL` topic from `secrets.env` in the ntfy app. The topic
name is the only thing protecting your alerts, so keep it secret. Then check the
path end to end:

```sh
bin/tattle test-alert
```

If you made a healthchecks.io check, set `HEARTBEAT_URL` in `secrets.env` and run
`bin/tattle deploy` again.

## Installing and upgrading

### Upgrading an existing deployment

Run `npm ci` in `worker/`, then add the `HOST_GATE` binding and SQLite migration
from `worker/wrangler.toml.example` to your private configuration while retaining
its existing bindings and migration history. `bin/tattle deploy` checks the TOML
and bundles the configured Worker before changing remote deployment or recovery
state. If either check fails, it prints the configuration problem and stops.
The deployment preflight requires Python 3.11 or newer; monitored machines do
not need Python.

Deploy the Worker before updating collectors. Existing collector report payloads
and historical archives remain readable. Re-run the installer on each monitored
machine to receive the root-path checks and bounded collection behavior.

The scheduled sweep automatically gives existing hosts with no report or
enrollment marker a fresh silence grace period, without rotating their tokens or
resetting existing report baselines. It processes up to 500 hosts each run;
larger fleets are covered over successive runs.

After deliberately re-enrolling a host, refresh its recognized Tattle canaries
using the new token:

```sh
curl -fsSL https://tattle.<you>.workers.dev/install.sh | sudo sh -s -- --prompt-token --refresh-canaries
```

Refresh preserves unrelated AWS profiles and SSH entries, saves restricted
backups of replaced files, and refuses ambiguous ownership or unsafe links.
Older `prod-secrets.env` files lack a unique Tattle marker: inspect and move only
the known old canary aside manually before retrying. Ordinary installation
continues to leave existing planted canaries in place.

### Enrolling a machine

```sh
bin/tattle add-host kitchen-imac
```

This shows a fresh token once and prints an install command. Run the command on
that machine, then paste the token at the hidden terminal prompt:

```sh
curl -fsSL https://tattle.<you>.workers.dev/install.sh | sudo sh -s -- --prompt-token
```

The installer puts the collector in `/usr/local/libexec/tattle`, the token in
`/etc/tattle/env` (mode 600), schedules a daily run between 2 and 7 am (launchd on
macOS, a systemd timer on Linux, cron otherwise), sends a first report and plants
canaries for the user who ran `sudo`. Add `--no-canaries` after `--prompt-token` to
skip the canaries. Re-running the command updates the collector.

The token is shown once. `hosts.json` in your deployment directory keeps only its
SHA-256 hash. Keep that file in your private deployment repo. Enrollment also
starts the 36-hour silence clock through a persistent enrollment-tagged marker,
so a machine that never sends its first report still raises an alert. Add/remove operations keep a recovery journal and serialize
operator changes; retry a failed operation to finish cleanup or rollback.

To see what a machine sends, run `sudo /usr/local/libexec/tattle/tattle-collect --print`.

## Day to day

```sh
bin/tattle status              # when each machine last reported
bin/tattle remove-host NAME    # revoke a machine's token
```

Alerts you can expect:

| alert | priority | meaning |
|---|---|---|
| `CANARY TRIPPED …` | max | someone used a planted fake credential. Treat the named machine as compromised. |
| `<host>: N security-relevant changes` | high | the daily diff found a new account, key, persistence item, network listener or posture change. Usually it's you; check. |
| `<host> has not reported for Nh` | high | the machine is off, offline, or the collector was stopped. |
| `<host> is reporting again` | normal | it came back. |

With the bucket lock and lifecycle rules above, reports expire after a year and
cannot be deleted for the first 90 days. These are deployment controls; the
Worker cannot establish them for you. `GET /reports` and `GET /report?key=…` with the read token return them, if
you want to feed them to something else. Default `/hosts` and `/reports` retain
the original complete `{hosts}` and `{keys}` responses within resource bounds;
oversized listings return an explicit error rather than a partial result.
Use `?pagination=1` to request `{hosts, cursor}` or `{keys, cursor}`, with optional
`limit=1..500` and an opaque `cursor`. A null cursor ends pagination. `status`
opts into pagination automatically and also works with the original Worker.
See [the API details](docs/design.md#read-api) for limits.

## Limits

- A root attacker on a machine can make its reports lie from then on. tattle
  catches the change that got them root only if it happened before the next
  snapshot left the box, and the canaries and silence alerts still work. That is
  why detection lives off the box.
- The daily diff is deliberately narrow, to keep alerts rare. It will miss things
  a full EDR would catch.
- iPhones and iPads can't run the collector. Keep them updated, and use Lockdown
  Mode for anyone at higher risk.
- ntfy.sh topics are public to anyone who knows the name. Use the long random
  name `tattle init` generates, or reserve a topic or run your own ntfy server
  and set `NTFY_TOKEN`.
- Each host can complete one report per hour. A Durable Object serializes
  admission across token rotations and bounds recovery attempts and canary provisioning. Authenticated
  rejected requests still consume Worker resources; this is not a total quota cap.
- A host token authorizes reports as that host and bounded canary enrollment
  through `/canaries.sh`; it cannot read reports or change deployment settings.
  `tattle remove-host` revokes it. Prefer `--prompt-token` to keep it out of shell
  history and process arguments. Legacy positional tokens remain supported and
  can appear in history and sudo logs.
- canarytokens.org is a free service run by Thinkst. If it is down, new canaries
  can't be minted and tripped ones may not alert.

## Development

```sh
cd worker && npm ci && npm test
```

The collector is plain POSIX `sh` and has to work under macOS `/bin/sh` (bash 3.2)
and dash. Test changes with `--print` on both.

## License

MIT
