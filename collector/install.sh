#!/bin/sh
# Install the tattle collector and schedule it daily.
#
#   curl -fsSL https://<your worker>/install.sh | sudo sh -s -- <host token> [--no-canaries]
#
# Re-running is safe: it updates the collector and keeps the schedule.
# Everything is inside main(), so a download cut short runs nothing.
set -eu

main() {
TOKEN=${1:-}
echo "$TOKEN" | grep -Eq '^[0-9a-f]{64}$' || { echo "usage: install.sh <host token> [--no-canaries]" >&2; exit 1; }
CANARIES=yes
[ "${2:-}" = --no-canaries ] || [ -n "${TATTLE_NO_CANARIES:-}" ] && CANARIES=
URL=__TATTLE_URL__
DIR=/usr/local/libexec/tattle

[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 1; }

mkdir -p "$DIR" /etc/tattle
curl -fsSL "$URL/tattle-collect" -o "$DIR/tattle-collect.new"
sh -n "$DIR/tattle-collect.new"
mv "$DIR/tattle-collect.new" "$DIR/tattle-collect"
chmod 755 "$DIR/tattle-collect"

umask 077
printf 'TATTLE_URL=%s\nTATTLE_TOKEN=%s\n' "$URL" "$TOKEN" >/etc/tattle/env
chmod 600 /etc/tattle/env

# Spread machines across the night so they don't all report at once.
HOUR=$(( $(od -An -N1 -tu1 /dev/urandom) % 5 + 2 ))
MIN=$(( $(od -An -N1 -tu1 /dev/urandom) % 60 ))

if [ "$(uname -s)" = Darwin ]; then
	PLIST=/Library/LaunchDaemons/dev.tattle.collect.plist
	cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>dev.tattle.collect</string>
	<key>ProgramArguments</key><array><string>/bin/sh</string><string>$DIR/tattle-collect</string></array>
	<key>StartCalendarInterval</key><dict><key>Hour</key><integer>$HOUR</integer><key>Minute</key><integer>$MIN</integer></dict>
	<key>RunAtLoad</key><true/>
	<key>StandardOutPath</key><string>/var/log/tattle.log</string>
	<key>StandardErrorPath</key><string>/var/log/tattle.log</string>
</dict>
</plist>
EOF
	chmod 644 "$PLIST"
	launchctl bootout system "$PLIST" 2>/dev/null || true
	launchctl bootstrap system "$PLIST"
	echo "tattle: installed, runs daily at $HOUR:$(printf %02d $MIN) and now (log: /var/log/tattle.log)"
elif command -v systemctl >/dev/null 2>&1; then
	cat >/etc/systemd/system/tattle.service <<EOF
[Unit]
Description=tattle security snapshot
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh $DIR/tattle-collect
Nice=10
IOSchedulingClass=idle
EOF
	cat >/etc/systemd/system/tattle.timer <<EOF
[Unit]
Description=Daily tattle security snapshot

[Timer]
OnCalendar=*-*-* $HOUR:$MIN:00
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
EOF
	systemctl daemon-reload
	systemctl enable --now tattle.timer
	systemctl start tattle.service --no-block
	echo "tattle: installed, runs daily around $HOUR:$(printf %02d $MIN) and now (journalctl -u tattle)"
else
	echo "$MIN $HOUR * * * root /bin/sh $DIR/tattle-collect >>/var/log/tattle.log 2>&1" >/etc/cron.d/tattle
	/bin/sh "$DIR/tattle-collect" >>/var/log/tattle.log 2>&1 &
	echo "tattle: installed via cron, runs daily at $HOUR:$(printf %02d $MIN)"
fi

# Canaries for the person who uses this machine (or root on a server).
# Pass --no-canaries to skip.
if [ -n "$CANARIES" ]; then
	if [ "$(uname -s)" = Darwin ]; then
		CUSER=${SUDO_USER:-$(stat -f%Su /dev/console)}
		CHOME=$(dscl . -read "/Users/$CUSER" NFSHomeDirectory | awk '{ print $2 }')
	else
		CUSER=${SUDO_USER:-root}
		CHOME=$(getent passwd "$CUSER" | cut -d: -f6)
	fi
	PLANT=$(mktemp)
	printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" | curl -fsS -K - "$URL/canaries.sh?user=$CUSER" -o "$PLANT"
	sh -n "$PLANT"
	# Feed the script on stdin: root's temp directory isn't readable by the
	# user, so the user's shell can't open the file itself.
	if [ "$CUSER" = root ]; then HOME=$CHOME sh <"$PLANT"; else sudo -u "$CUSER" HOME="$CHOME" sh <"$PLANT"; fi
	rm -f "$PLANT"
fi
}

main "$@"
