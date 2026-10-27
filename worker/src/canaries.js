// Canaries: fake credentials nobody legitimate ever uses. The worker mints
// fresh canarytokens.org tokens for one machine and returns a shell script that
// plants them in the calling user's home. Tokens report to this worker's
// /canary endpoint, and each memo names the host and file, so an alert says
// exactly which machine and which file was touched.

const CANARYTOKENS = "https://canarytokens.org/d3aece8093b71007b5ccfedad91ebb11/generate";
const MARK = "tattle-canary";

export async function mintCanaries(env, origin, where, callbackKey = env.CANARY_KEY) {
	const mint = async (type, memo) => {
		const res = await fetch(CANARYTOKENS, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				token_type: type,
				memo: `tattle: ${where} ${memo}`,
				email: env.CANARY_EMAIL || "",
				webhook_url: `${origin}/canary?key=${encodeURIComponent(callbackKey)}`,
			}),
		});
		const token = await res.json();
		if (!res.ok || !token || typeof token !== "object" || Array.isArray(token) || token.error) throw new Error(`canarytokens ${type}: provider response failed`);
		return token;
	};
	const [aws, envFile, dns] = await Promise.all([
		mint("aws_keys", "~/.aws/credentials [backup-admin]"),
		mint("aws_keys", "~/Documents/prod-secrets.env"),
		mint("dns", "~/.ssh/config Host db-backup-prod"),
	]);
	return validateCanaries({ aws, envFile, dns });
}

// Reject malformed provider data before it reaches a shell heredoc. Do not
// coerce or sanitize invalid values into credentials that cannot trip.
const invalidResponse = () => new Error("canarytokens.org response has an invalid or missing field");
const record = (value) => {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw invalidResponse();
	return value;
};
const tokenField = (value) => {
	if (typeof value !== "string" || !/^[A-Za-z0-9+/=._-]+$/.test(value)) throw invalidResponse();
	return value;
};
const credentials = (value) => {
	const data = record(value);
	const region = data.region === undefined ? "us-east-2" : data.region;
	if (typeof region !== "string" || !/^[a-z]{2}(?:-[a-z]+)+-[0-9]+$/.test(region)) throw invalidResponse();
	return {
		aws_access_key_id: tokenField(data.aws_access_key_id),
		aws_secret_access_key: tokenField(data.aws_secret_access_key),
		region,
	};
};
const hostname = (value) => {
	if (typeof value !== "string" || value.length > 253) throw invalidResponse();
	const labels = value.replace(/\.$/, "").split(".");
	if (labels.length < 2 || !/[A-Za-z]/.test(labels.at(-1)) ||
		!labels.every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label))) throw invalidResponse();
	return value;
};

export function validateCanaries(value) {
	try {
		const data = record(value);
		return { aws: credentials(data.aws), envFile: credentials(data.envFile), dns: { hostname: hostname(record(data.dns).hostname) } };
	} catch {
		throw invalidResponse();
	}
}

export function plantScript(value) {
	const { aws, envFile, dns } = validateCanaries(value);
	return `#!/bin/sh
# Tattle canaries. --refresh replaces only recognized Tattle-owned blocks.
set -eu
umask 077
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
REFRESH=
case "\${1:-}" in '') [ "$#" -eq 0 ] || exit 1;; --refresh) [ "$#" -eq 1 ] || exit 1; REFRESH=yes;; *) echo "usage: canaries.sh [--refresh]" >&2; exit 1;; esac
fail() { echo "tattle canaries: $*" >&2; exit 1; }
OS=$(uname -s)
UID_NOW=$(id -u)
TMP=
BACKUP=
cleanup() {
	if [ -n "$TMP" ] && [ -f "$TMP" ] && [ ! -L "$TMP" ]; then unlink "$TMP"; fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
meta() {
	if [ "$OS" = Darwin ]; then stat -f '%u %Lp %l' "$1"; else stat -c '%u %a %h' "$1"; fi
}
check() {
	[ ! -L "$1" ] || fail "symlink refused: $1"
	set -- "$1" $(meta "$1")
	[ "$#" -eq 4 ] || fail "cannot inspect path"
	[ "$2" = "$UID_NOW" ] || [ "$2" = 0 ] || fail "untrusted owner: $1"
	if [ $((0$3 & 0022)) -ne 0 ]; then
		# Root-owned sticky ancestors (e.g. /tmp) protect each user's entries.
		[ -d "$1" ] && [ "$2" = 0 ] && [ $((0$3 & 01000)) -ne 0 ] || fail "unsafe permissions: $1"
	fi
	if [ -f "$1" ]; then
		[ "$2" = "$UID_NOW" ] && [ "$4" = 1 ] || fail "file owner or hardlink refused: $1"
	fi
	if [ "$OS" = Darwin ]; then
		ACL=$(ls -lde "$1") || fail "cannot inspect ACL"
		printf '%s\\n' "$ACL" | awk 'NR > 1 && / allow / && /write|append|delete|add_file|add_subdirectory|chown/ { bad=1 } END { exit bad }' || fail "writable ACL refused: $1"
	elif command -v getfacl >/dev/null 2>&1; then
		ACL=$(getfacl -cp "$1") || fail "cannot inspect ACL"
		printf '%s\\n' "$ACL" | awk -F: '/^(default:)?(user|group):/ && /w/ { if ($1 == "default" || $2 != "") bad=1 } END { exit bad }' || fail "writable ACL refused: $1"
	else
		ACL=$(LC_ALL=C ls -ld "$1") || fail "cannot inspect ACL"
		case \${ACL%% *} in *+*) fail "ACL reader required: $1";; esac
	fi
}
# macOS supplies these root-owned OS aliases; validate their exact destination.
# Other symlinks anywhere in HOME or a canary path remain forbidden.
if [ "$OS" = Darwin ]; then
	case "$HOME" in
		/var/*) [ "$(readlink /var)" = private/var ] || fail "unexpected /var alias"; HOME=/private/var/\${HOME#/var/} ;;
		/tmp/*) [ "$(readlink /tmp)" = private/tmp ] || fail "unexpected /tmp alias"; HOME=/private/tmp/\${HOME#/tmp/} ;;
	esac
fi
case "$HOME" in /*) ;; *) fail "HOME must be absolute";; esac
REST=\${HOME#/}
NODE=/
check /
while [ -n "$REST" ]; do
	PART=\${REST%%/*}
	case "$PART" in ''|.|..) fail "HOME must be canonical";; esac
	case "$REST" in */*) REST=\${REST#*/};; *) REST=;; esac
	NODE=\${NODE%/}/$PART
	[ -d "$NODE" ] || fail "missing HOME directory: $NODE"
	check "$NODE"
done
[ "$NODE" = "$HOME" ] && [ "$HOME" != / ] || fail "HOME must be canonical and non-root"
set -- $(meta "$HOME")
[ "$1" = "$UID_NOW" ] || fail "HOME owner mismatch"
[ $((0$2 & 0022)) -eq 0 ] || fail "unsafe HOME permissions"
for DIR in "$HOME/.aws" "$HOME/.ssh" "$HOME/Documents"; do
	[ ! -L "$DIR" ] || fail "symlink refused: $DIR"
	if [ ! -e "$DIR" ]; then mkdir -m 700 "$DIR"; fi
	[ -d "$DIR" ] || fail "not a directory: $DIR"
	check "$DIR"
	set -- $(meta "$DIR")
	[ $((0$2 & 0022)) -eq 0 ] || fail "unsafe canary directory permissions: $DIR"
done
AWS_FILE=$HOME/.aws/credentials
ENV_FILE=$HOME/Documents/prod-secrets.env
SSH_FILE=$HOME/.ssh/config
for FILE in "$AWS_FILE" "$ENV_FILE" "$SSH_FILE"; do
	[ ! -L "$FILE" ] || fail "symlink refused: $FILE"
	if [ -e "$FILE" ]; then
		[ -f "$FILE" ] || fail "not a regular file: $FILE"
		check "$FILE"
	fi
done
# Return either append/skip or the exact inclusive line range of one owned block.
# Reject duplicate markers, malformed blocks, or extra directives in that section.
plan() {
	FILE=$1
	KIND=$2
	[ -e "$FILE" ] || { echo append; return; }
	if [ -z "$REFRESH" ]; then
		if grep -q 'tattle-canary' "$FILE" || [ "$KIND" = env ]; then echo skip; return; fi
	fi
	awk -v kind="$KIND" '
	function token(s) { return s ~ /^[A-Za-z0-9+\\/=._-]+$/ }
	function region(s) { return s ~ /^[a-z][a-z](-[a-z]+)+-[0-9]+$/ }
	function bad() { exit 1 }
	{ line[NR]=$0; if ($0 ~ /^[ \t]*#.*tattle-canary/) markers++ }
	END {
		begin="# tattle-canary: begin " kind " v1"; end="# tattle-canary: end " kind " v1"
		for (i=1;i<=NR;i++) {
			if (line[i]==begin) { if (start) bad(); start=i; modern=1 }
			if (line[i]=="# tattle-canary: do not use" && !modern) { if (start) bad(); start=i }
		}
		if (!start) {
			if (markers || kind=="env") bad()
			for (i=1;i<=NR;i++) {
				if (kind=="aws" && line[i] ~ /^[ \t]*\\[backup-admin\\]/) bad()
				if (kind=="ssh" && tolower(line[i]) ~ /^[ \t]*host[ \t=]+/ && index(tolower(line[i]),"db-backup-prod")) bad()
			}
			print "append"; exit
		}
		s=start+modern
		if (kind=="aws") {
			if (line[s]!="# tattle-canary: do not use" || line[s+1]!="[backup-admin]" || line[s+2] !~ /^aws_access_key_id = / || !token(substr(line[s+2],21)) || line[s+3] !~ /^aws_secret_access_key = / || !token(substr(line[s+3],25)) || line[s+4] !~ /^region = / || !region(substr(line[s+4],10))) bad()
			last=s+4
		} else if (kind=="ssh") {
			if (line[s]!="# tattle-canary: do not use" || line[s+1]!="Host db-backup-prod" || line[s+2] !~ /^  HostName [A-Za-z0-9][A-Za-z0-9.-]+$/ || line[s+3]!="  User root") bad()
			last=s+3
		} else {
			if (!modern || line[s]!="# production backup credentials (rotated quarterly)" || line[s+1] !~ /^AWS_ACCESS_KEY_ID=/ || !token(substr(line[s+1],19)) || line[s+2] !~ /^AWS_SECRET_ACCESS_KEY=/ || !token(substr(line[s+2],23)) || line[s+3] !~ /^AWS_DEFAULT_REGION=/ || !region(substr(line[s+3],20)) || line[s+4]!="S3_BACKUP_BUCKET=prod-db-backups") bad()
			last=s+4
		}
		if (modern) { last++; if (line[last]!=end || markers!=(kind=="env" ? 2 : 3)) bad() }
		else if (markers!=1) bad()
		if (kind=="env" && (start!=1 || last!=NR)) bad()
		# Require the next directive to begin a distinct section; preserve comments.
		for (i=last+1;i<=NR;i++) {
			if (line[i] ~ /^[ \t]*(#.*)?$/) continue
			if (kind=="aws" && line[i] !~ /^\\[[^][]+\\]$/) bad()
			if (kind=="ssh" && tolower(line[i]) !~ /^[ \t]*(host|match)[ \t=]+/) bad()
			break
		}
		# An additional target section anywhere would make ownership ambiguous.
		for (i=1;i<=NR;i++) if (i<start || i>last) {
			if (kind=="aws" && line[i] ~ /^[ \t]*\\[backup-admin\\]/) bad()
			if (kind=="ssh" && tolower(line[i]) ~ /^[ \t]*host[ \t=]+/ && index(tolower(line[i]),"db-backup-prod")) bad()
		}
		print start, last
	}' "$FILE" || fail "cannot establish Tattle ownership: $FILE; preserve it, inspect its contents, and manually migrate only confirmed old Tattle canaries before retrying --refresh"
}
AWS_PLAN=$(plan "$AWS_FILE" aws)
ENV_PLAN=$(plan "$ENV_FILE" env)
SSH_PLAN=$(plan "$SSH_FILE" ssh)
block() {
	case "$1" in
	aws) cat <<'CANARY'
# tattle-canary: begin aws v1
# tattle-canary: do not use
[backup-admin]
aws_access_key_id = ${aws.aws_access_key_id}
aws_secret_access_key = ${aws.aws_secret_access_key}
region = ${aws.region}
# tattle-canary: end aws v1
CANARY
	;;
	env) cat <<'CANARY'
# tattle-canary: begin env v1
# production backup credentials (rotated quarterly)
AWS_ACCESS_KEY_ID=${envFile.aws_access_key_id}
AWS_SECRET_ACCESS_KEY=${envFile.aws_secret_access_key}
AWS_DEFAULT_REGION=${envFile.region}
S3_BACKUP_BUCKET=prod-db-backups
# tattle-canary: end env v1
CANARY
	;;
	ssh) cat <<'CANARY'
# tattle-canary: begin ssh v1
# tattle-canary: do not use
Host db-backup-prod
  HostName ${dns.hostname}
  User root
# tattle-canary: end ssh v1
CANARY
	;;
	esac
}
planted=""
replace() {
	FILE=$1
	KIND=$2
	PLAN=$3
	LABEL=$4
	[ "$PLAN" != skip ] || return 0
	TMP=$(mktemp "\${FILE%/*}/.tattle-canary.XXXXXXXXXX") || fail "cannot create temporary file"
	if [ "$PLAN" = append ]; then
		if [ -e "$FILE" ]; then cat "$FILE" >"$TMP"; printf '\\n' >>"$TMP"; fi
		block "$KIND" >>"$TMP"
	else
		set -- $PLAN
		if [ "$1" -gt 1 ]; then head -n "$(($1 - 1))" "$FILE" >"$TMP"; fi
		block "$KIND" >>"$TMP"
		tail -n "+$(($2 + 1))" "$FILE" >>"$TMP"
		if cmp -s "$TMP" "$FILE"; then unlink "$TMP"; TMP=; return 0; fi
	fi
	if [ -e "$FILE" ]; then
		check "$FILE"
		BACKUP=$(mktemp "\${FILE%/*}/.tattle-canary-backup.XXXXXXXXXX") || fail "cannot create backup"
		cat "$FILE" >"$BACKUP" || fail "cannot write backup"
		echo "tattle canaries: backup saved: $BACKUP" >&2
	fi
	chmod 600 "$TMP"
	mv -f "$TMP" "$FILE"
	TMP=
	planted="$planted $LABEL"
}
replace "$AWS_FILE" aws "$AWS_PLAN" '~/.aws/credentials'
replace "$ENV_FILE" env "$ENV_PLAN" '~/Documents/prod-secrets.env'
replace "$SSH_FILE" ssh "$SSH_PLAN" '~/.ssh/config'
echo "tattle canaries:\${planted:- already planted}"
`;
}
