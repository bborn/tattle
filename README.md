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
  The Worker compares it with the previous day's and emails you when something
  security-relevant changes: a new admin, a new SSH key, a
  new launch daemon, a process newly open to the network, FileVault or the
  firewall turned off.
- **Silence alerts.** If a machine stops reporting for 36 hours, you get an alert.
  An attacker who disables the collector can't make that alert go away.
- **Canaries.** At install, tattle plants fake AWS keys and a fake SSH host in
  each user's home directory, using free canarytokens.org tokens. Nobody
  legitimate ever uses them, so if one is used you get an email naming the
  machine and the file, usually within seconds.

Everything runs on free tiers: Cloudflare Workers, R2, KV and Email Routing, and
canarytokens.org. There is no agent to install beyond one POSIX shell script, and
no AI runs on the monitored machines.

See [docs/design.md](docs/design.md) for how it works and why, and
[docs/hardening.md](docs/hardening.md) for the short list of fixes that most
reduce blast radius. Most of them came up in real audits of real machines.

## What you need

- A Cloudflare account. **Use a new one that you use for nothing else**, and keep
  its credentials off every machine you monitor. Anyone with a `wrangler` login to
  the monitoring account can delete the Worker and silence every alert.
- A domain on that account with Email Routing turned on, so tattle has an
  address to send from, and your own address added there as a verified
  destination. That's where alerts will go.
- Node.js (for `npx wrangler`), `python3` and `curl` on the machine you operate
  from.
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

# 1. Cloudflare resources (logged in to the monitoring account)
npx wrangler login
npx wrangler r2 bucket create tattle-reports
npx wrangler r2 bucket lock add tattle-reports keep-90d "" --retention-days 90
npx wrangler r2 bucket lifecycle add tattle-reports expire-1y "" --expire-days 365
npx wrangler kv namespace create STATE    # note the id it prints

# 2. Worker config
cp worker/wrangler.toml.example "$TATTLE_DEPLOY/wrangler.toml"
# edit it: put the KV namespace id and your email addresses in

# 3. Secrets, then deploy
bin/tattle init        # writes ~/.config/tattle/secrets.env (read token, canary key)
bin/tattle deploy      # prints the Worker URL
# put that URL in TATTLE_URL in ~/.config/tattle/secrets.env
```

Then check the alert path end to end. You should get an email:

```sh
bin/tattle test-alert
```

If you made a healthchecks.io check, set `HEARTBEAT_URL` in `secrets.env` and run
`bin/tattle deploy` again.

## Adding a machine

```sh
bin/tattle add-host kitchen-imac
```

This prints a one-line install command with a fresh token. Run it on that
machine:

```sh
curl -fsSL https://tattle.<you>.workers.dev/install.sh | sudo sh -s -- <token>
```

The installer puts the collector in `/usr/local/libexec/tattle`, the token in
`/etc/tattle/env` (mode 600), schedules a daily run between 2 and 7 am (launchd on
macOS, a systemd timer on Linux, cron otherwise), sends a first report and plants
canaries for the user who ran `sudo`. Add `--no-canaries` after the token to
skip the canaries. Re-running the command updates the collector.

The token is shown once. `hosts.json` in your deployment directory keeps only its
SHA-256 hash, so it is safe to commit to your private repo.

To see what a machine sends, run `sudo /usr/local/libexec/tattle/tattle-collect --print`.

## Day to day

```sh
bin/tattle status              # when each machine last reported
bin/tattle remove-host NAME    # revoke a machine's token
```

Alerts you can expect (all by email):

| alert | priority | meaning |
|---|---|---|
| `CANARY TRIPPED …` | max | someone used a planted fake credential. Treat the named machine as compromised. |
| `<host>: N security-relevant changes` | high | the daily diff found a new account, key, persistence item, network listener or posture change. Usually it's you; check. |
| `<host> has not reported for Nh` | high | the machine is off, offline, or the collector was stopped. |
| `<host> is reporting again` | normal | it came back. |

Reports are kept for a year and can't be deleted for the first 90 days, even by
you. `GET /reports` and `GET /report?key=…` with the read token return them, if
you want to feed them to something else.

## Limits

- A root attacker on a machine can make its reports lie from then on. tattle
  catches the change that got them root only if it happened before the next
  snapshot left the box, and the canaries and silence alerts still work. That is
  why detection lives off the box.
- The daily diff is deliberately narrow, to keep alerts rare. It will miss things
  a full EDR would catch.
- iPhones and iPads can't run the collector. Keep them updated, and use Lockdown
  Mode for anyone at higher risk.
- Alerts go to one inbox. If you'd rather have canary trips on your phone too,
  see "Phone push" below.
- Each machine can report at most once an hour, so one compromised machine
  can't use up the free-tier quotas the other machines' alerts depend on.
- The install command puts the host token on the command line once, so it can
  end up in shell history and the sudo log. All the token can do is send
  reports as that machine, and `tattle remove-host` revokes it.
- canarytokens.org is a free service run by Thinkst. If it is down, new canaries
  can't be minted and tripped ones may not alert.

## Phone push (optional)

Set `NTFY_URL` in `secrets.env` to an [ntfy](https://ntfy.sh) topic URL with a
long random name and run `bin/tattle deploy`. Canary trips will then also go to
that topic, and if email isn't configured, every alert will. If a push fails
and the email gets through, the alert still counts as delivered.

ntfy.sh limits anonymous senders by IP address, and Cloudflare Workers share
their IP addresses with everyone else's Workers, so anonymous pushes from the
Worker often fail on the daily quota. Make a free ntfy.sh account and add its
access token as the `NTFY_TOKEN` secret so the quota is yours alone. Anyone who
knows the topic name can read and send to it, so keep it secret.

## Development

```sh
cd worker && npm install && npm test
```

The collector is plain POSIX `sh` and has to work under macOS `/bin/sh` (bash 3.2)
and dash. Test changes with `--print` on both.

## License

MIT
