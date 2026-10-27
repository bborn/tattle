#!/bin/sh
# Install the tattle collector and schedule it daily.
#
#   curl -fsSL https://<your worker>/install.sh | sudo sh -s -- --prompt-token [--no-canaries|--refresh-canaries]
#
# Re-running is safe: it updates the collector and keeps the schedule.
# Installation starts only at the final main call, after the script is complete.
# Legacy positional tokens work; saved scripts can also use --token-stdin.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

fail() { echo "tattle: $*" >&2; exit 1; }

# Trusted ancestors make subsequent checks and atomic replacements race-safe.
# Never repair an untrusted existing directory into a privileged installation.
check_node() {
	[ ! -L "$1" ] || fail "symlink refused: $1"
	if [ "$OS" = Darwin ]; then
		META=$(stat -f '%u %Lp' "$1") || fail "cannot stat $1"
	else
		META=$(stat -c '%u %a' "$1") || fail "cannot stat $1"
	fi
	set -- "$1" $META
	[ "$2" = "$OWNER_UID" ] || fail "non-root owner: $1"
	[ $((0$3 & 0022)) -eq 0 ] || fail "writable by group/others: $1"
	if [ "$OS" = Darwin ]; then
		# macOS reports ACL entries after the ordinary ls metadata line.
		ACL=$(ls -lde "$1") || fail "cannot inspect ACL: $1"
		printf '%s\n' "$ACL" | awk 'NR > 1 && / allow / && /write|append|delete|add_file|add_subdirectory|chown/ { if ($0 !~ /user:root / && $0 !~ /group:admin /) bad=1 } END { exit bad }' || fail "unsafe ACL: $1"
	elif command -v getfacl >/dev/null 2>&1; then
		ACL=$(getfacl -cp "$1") || fail "cannot inspect ACL: $1"
		# Reject named/default write grants, even if currently masked off.
		printf '%s\n' "$ACL" | awk -F: '/^(default:)?(user|group):/ && /w/ { if ($1 == "default" || ($2 != "" && $2 != "root" && $2 != "0")) bad=1 } END { exit bad }' || fail "unsafe ACL: $1"
	else
		# '+' indicates an extended ACL. Without an ACL reader fail closed.
		ACL=$(LC_ALL=C ls -ld "$1") || fail "cannot inspect ACL: $1"
		case ${ACL%% *} in *+*) fail "ACL reader required: $1";; esac
	fi
}

safe_dir() {
	case "$1" in /*) ;; *) fail "non-absolute directory: $1";; esac
	REST=${1#/}
	NODE=/
	check_node /
	while [ -n "$REST" ]; do
		PART=${REST%%/*}
		case "$PART" in ''|.|..) fail "non-canonical directory: $1";; esac
		case "$REST" in */*) REST=${REST#*/};; *) REST=;; esac
		NODE=${NODE%/}/$PART
		[ ! -L "$NODE" ] || fail "symlink refused: $NODE"
		if [ ! -e "$NODE" ]; then
			mkdir -m 755 "$NODE"
			chown "$OWNER_UID" "$NODE"
		fi
		[ -d "$NODE" ] || fail "not a directory: $NODE"
		check_node "$NODE"
	done
}

safe_target() {
	safe_dir "${1%/*}"
	[ ! -L "$1" ] || fail "symlink refused: $1"
	if [ -e "$1" ]; then
		[ -f "$1" ] || fail "not a regular file: $1"
		check_node "$1"
	fi
}

new_temp() {
	# mktemp creates an exclusive 0600 regular file in a trusted directory.
	TEMP_DIR=${1:-$DIR}
	safe_dir "$TEMP_DIR"
	TMP=$(mktemp "$TEMP_DIR/.tattle-install.XXXXXXXXXX") || fail "cannot create temporary file"
	[ -f "$TMP" ] && [ ! -L "$TMP" ] || fail "unsafe temporary file"
	TEMPS="$TEMPS $TMP"
}

publish() {
	safe_target "$1"
	chown "$OWNER_UID" "$TMP"
	chmod "$2" "$TMP"
	mv -f "$TMP" "$1"
}

cleanup() {
	# Only exact mktemp names from our validated private namespace are removed.
	for CLEAN in $TEMPS; do
		case "$CLEAN" in /*/.tattle-install.*)
			[ ! -L "$CLEAN" ] && [ -f "$CLEAN" ] && unlink "$CLEAN" || : ;;
		esac
	done
}

main() {
TOKEN=${1:-}
case "$TOKEN" in
	--prompt-token)
		printf 'Host token: ' >/dev/tty
		stty -echo </dev/tty || fail "cannot disable terminal echo"
		trap 'stty echo </dev/tty' EXIT
		trap 'exit 1' HUP INT TERM
		if IFS= read -r TOKEN </dev/tty; then TOKEN_READ=yes; else TOKEN_READ=; fi
		stty echo </dev/tty
		trap - EXIT HUP INT TERM
		printf '\n' >/dev/tty
		[ -n "$TOKEN_READ" ] || fail "cannot read host token"
		;;
	--token-stdin) IFS= read -r TOKEN || fail "cannot read host token" ;;
esac
printf '%s\n' "$TOKEN" | grep -Eq '^[0-9a-f]{64}$' || { echo "usage: install.sh <host token>|--prompt-token|--token-stdin [--no-canaries|--refresh-canaries]" >&2; exit 1; }
shift
CANARIES=yes
REFRESH_CANARIES=
[ -z "${TATTLE_NO_CANARIES:-}" ] || CANARIES=
for OPTION in "$@"; do
	case "$OPTION" in
		--no-canaries) CANARIES= ;;
		--refresh-canaries) REFRESH_CANARIES=yes ;;
		*) fail "unknown option: $OPTION" ;;
	esac
done
[ -z "$REFRESH_CANARIES" ] || [ -n "$CANARIES" ] || fail "--refresh-canaries conflicts with disabled canaries"
URL='__TATTLE_URL__'
printf '%s\n' "$URL" | grep -Eq '^https://[A-Za-z0-9.-]+(:[0-9]+)?$' || fail "invalid HTTPS origin"
DIR=/usr/local/libexec/tattle

OWNER_UID=0
[ "$(id -u)" = "$OWNER_UID" ] || fail "run as root (sudo)"
OS=$(uname -s)
# /etc is an OS-provided symlink on macOS; use its canonical destination.
ETC=/etc
[ "$OS" != Darwin ] || ETC=/private/etc
TEMPS=
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
safe_dir "$DIR"
safe_dir "$ETC/tattle"
safe_target "$DIR/tattle-collect"
safe_target "$ETC/tattle/env"
new_temp
curl -fsSL "$URL/tattle-collect" -o "$TMP"
sh -n "$TMP"
publish "$DIR/tattle-collect" 755

new_temp "$ETC/tattle"
printf "TATTLE_URL='%s'\nTATTLE_TOKEN='%s'\n" "$URL" "$TOKEN" >"$TMP"
sh -n "$TMP"
publish "$ETC/tattle/env" 600

# Validate the privileged log destination before starting any scheduler.
LOG=/var/log
[ "$OS" != Darwin ] || LOG=/private/var/log
safe_target "$LOG/tattle.log"
if [ ! -e "$LOG/tattle.log" ]; then
	new_temp "$LOG"
	publish "$LOG/tattle.log" 644
fi

# Spread machines across the night so they don't all report at once.
HOUR=$(( $(od -An -N1 -tu1 /dev/urandom) % 5 + 2 ))
MIN=$(( $(od -An -N1 -tu1 /dev/urandom) % 60 ))

if [ "$OS" = Darwin ]; then
	PLIST=/Library/LaunchDaemons/dev.tattle.collect.plist
	safe_target "$PLIST"
	new_temp "${PLIST%/*}"
	cat >"$TMP" <<EOF
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
	publish "$PLIST" 644
	launchctl bootout system "$PLIST" 2>/dev/null || true
	launchctl bootstrap system "$PLIST"
	echo "tattle: installed, runs daily at $HOUR:$(printf %02d $MIN) and now (log: /var/log/tattle.log)"
elif command -v systemctl >/dev/null 2>&1; then
	safe_target "$ETC/systemd/system/tattle.service"
	safe_target "$ETC/systemd/system/tattle.timer"
	new_temp "$ETC/systemd/system"
	cat >"$TMP" <<EOF
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
	publish "$ETC/systemd/system/tattle.service" 644
	new_temp "$ETC/systemd/system"
	cat >"$TMP" <<EOF
[Unit]
Description=Daily tattle security snapshot

[Timer]
OnCalendar=*-*-* $HOUR:$MIN:00
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
EOF
	publish "$ETC/systemd/system/tattle.timer" 644
	systemctl daemon-reload
	systemctl enable --now tattle.timer
	systemctl start tattle.service --no-block
	echo "tattle: installed, runs daily around $HOUR:$(printf %02d $MIN) and now (journalctl -u tattle)"
else
	safe_target "$ETC/cron.d/tattle"
	new_temp "$ETC/cron.d"
	echo "$MIN $HOUR * * * root /bin/sh $DIR/tattle-collect >>/var/log/tattle.log 2>&1" >"$TMP"
	publish "$ETC/cron.d/tattle" 644
	/bin/sh "$DIR/tattle-collect" >>/var/log/tattle.log 2>&1 &
	echo "tattle: installed via cron, runs daily at $HOUR:$(printf %02d $MIN)"
fi

# Canaries for the person who uses this machine (or root on a server).
# Pass --no-canaries to skip.
if [ -n "$CANARIES" ]; then
	if [ "$OS" = Darwin ]; then
		CUSER=${SUDO_USER:-$(stat -f%Su /dev/console)}
	else
		CUSER=${SUDO_USER:-root}
	fi
	case "$CUSER" in *'
'*) fail "invalid canary user";; esac
	printf '%s\n' "$CUSER" | grep -Eq '^[A-Za-z0-9_][A-Za-z0-9_.-]*$' || fail "invalid canary user"
	CUID=$(id -u "$CUSER") || fail "unknown canary user"
	case "$CUID" in ''|*[!0-9]*) fail "invalid canary user id";; esac
	if [ "$OS" = Darwin ]; then
		CHOME=$(dscl . -read "/Users/$CUSER" NFSHomeDirectory | sed 's/^NFSHomeDirectory: //')
	else
		CHOME=$(getent passwd "$CUSER" | cut -d: -f6)
	fi
	case "$CHOME" in
		*'
'*) fail "invalid canary home";;
		/*) [ -d "$CHOME" ] || fail "missing canary home";;
		*) fail "invalid canary home";;
	esac
	new_temp
	PLANT=$TMP
	printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" | curl -fsS -K - "$URL/canaries.sh?user=$CUSER" -o "$PLANT"
	sh -n "$PLANT"
	# The download can embed fake credentials; only its intended user may read it.
	chown "$CUID" "$PLANT"
	chmod 600 "$PLANT"
	set -- "$PLANT"
	[ -z "$REFRESH_CANARIES" ] || set -- "$@" --refresh
	if [ "$CUSER" = root ]; then HOME=$CHOME sh "$@"; else sudo -u "$CUSER" HOME="$CHOME" sh "$@"; fi
	unlink "$PLANT"
fi
}

main "$@"
