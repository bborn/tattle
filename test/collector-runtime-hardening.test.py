#!/usr/bin/env python3
"""Harmless shell fixtures; no privileged writes, network, or secret reads."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'collector/tattle-collect').read_text()
OS = subprocess.check_output(['uname', '-s'], text=True).strip()


def block(start, end):
    return SOURCE[SOURCE.index(start):SOURCE.index(end)]


COMMON = ('set -u\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\nexport PATH LC_ALL=C\n'
          f'OS={OS}\nADMIN_GID=' + ('80' if OS == 'Darwin' else '0') + '\n' +
          block('have() {', '# Tools that may') +
          block('secure_node() {', '\n# Load trusted configuration') +
          block('jstr() {', '\nssh_keys()'))


class CollectorRuntime(unittest.TestCase):
    def run_shell(self, script, timeout=45, binary=False):
        with tempfile.TemporaryDirectory(prefix='tattle-fixture-') as temp:
            env = dict(os.environ, FIXTURE=str(Path(temp).resolve()))
            result = subprocess.run(['sh', '-c', COMMON + '\nTMP=$FIXTURE\n' + script],
                                    capture_output=True, env=env, timeout=timeout)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            return result.stdout if binary else result.stdout.decode()

    def test_config_validates_canonical_file_before_sourcing(self):
        # Real mode/ACL checks run on an unprivileged fixture. Only ownership
        # and ancestry outside this fixture simulate the installed root tree.
        body = block('secure_node() {', '\nstat_owner()').replace('secure_node() {', 'real_secure_node() {')
        output = self.run_shell(body + '''
stat_owner() { printf '0\\n'; }
getfacl() { printf 'user::rw-\\ngroup::r--\\nother::---\\n'; }
secure_node() {
 case $1 in "$FIXTURE"/*|"$FIXTURE") real_secure_node "$1";; *) return 0;; esac
}
mkdir "$FIXTURE/safe"
printf 'TATTLE_LYNIS=always\\nTATTLE_TOKEN=fixture-token\\n' >"$FIXTURE/safe/env"
chmod 600 "$FIXTURE/safe/env"
[ "$(trusted_file "$FIXTURE/safe/env")" = "$FIXTURE/safe/env" ] || exit 51
! trusted "$FIXTURE/safe/env" || exit 52
load_config upload "$FIXTURE/safe/env" || exit 53
[ "$TATTLE_LYNIS" = always ] && [ "$TATTLE_TOKEN" = fixture-token ] || exit 54
# Unsafe target must never execute the appended shell command.
printf 'printf leaked >"$TMP/source-marker"\\n' >>"$FIXTURE/safe/env"
ln -s safe/env "$FIXTURE/link"
chmod 666 "$FIXTURE/safe/env"
! load_config upload "$FIXTURE/link" 2>"$TMP/errors" || exit 55
[ ! -e "$TMP/source-marker" ] || exit 56
grep -q 'collector: missing or unsafe configuration:' "$TMP/errors" || exit 57
chmod 600 "$FIXTURE/safe/env"
chmod 777 "$FIXTURE/safe"
! load_config upload "$FIXTURE/link" 2>"$TMP/errors" || exit 58
[ ! -e "$TMP/source-marker" ] || exit 59
! load_config upload "$FIXTURE/missing" 2>"$TMP/errors" || exit 63
grep -q 'collector: missing or unsafe configuration:' "$TMP/errors" || exit 64
# Print mode bypasses even validation and never sources a readable config.
trusted_file() { printf unexpected >"$TMP/validation-marker"; return 1; }
load_config --print "$FIXTURE/safe/env" || exit 60
load_config --print "$FIXTURE/missing" || exit 61
[ ! -e "$TMP/source-marker" ] && [ ! -e "$TMP/validation-marker" ] || exit 62
printf passed
''')
        self.assertEqual(output, 'passed')
        self.assertNotIn('[ -r /etc/tattle/env ] && . /etc/tattle/env', SOURCE)
        self.assertLess(SOURCE.index('load_config "${1:-}" /etc/tattle/env'), SOURCE.index('TAILSCALE=$(trusted'))

    def test_mac_cron_metadata_never_emits_commands(self):
        helper = block('mac_cron_metadata() {', '\nmac_persistence()')
        output = self.run_shell(helper + '''
crontab() { printf '%s\\n' "$CRON_FIXTURE"; }
CRON_FIXTURE='  # comment containing SYNTHETIC_CRON_SECRET

  */5 * * * * fetch --token=SYNTHETIC_CRON_SECRET  '
mac_cron_metadata fixture-user
CRON_FIXTURE='*/5 * * * * fetch --token=SYNTHETIC_CRON_SECRET'
mac_cron_metadata fixture-user
CRON_FIXTURE='*/6 * * * * fetch --token=SYNTHETIC_CRON_SECRET'
mac_cron_metadata fixture-user
''')
        self.assertNotIn('SYNTHETIC_CRON_SECRET', output)
        self.assertNotIn('fetch', output)
        records = output.splitlines()
        self.assertEqual(len(records), 3)
        self.assertTrue(all('entries:1 ' in record for record in records))
        self.assertTrue(all('user-hex:666978747572652d75736572 ' in record for record in records))
        self.assertEqual(records[0], records[1])
        self.assertNotEqual(records[1].split('sha256:')[1], records[2].split('sha256:')[1])

    def test_missing_optional_executables_are_quiet(self):
        output = self.run_shell('''
secure_node() { printf 'unexpected validation of %s\\n' "$1" >&2; return 1; }
! trusted "$FIXTURE/missing" "$FIXTURE/also-missing" 2>"$TMP/errors" || exit 41
[ ! -s "$TMP/errors" ] || exit 42
# A dangling symlink is considered, and its nonexistent resolved component
# is rejected quietly rather than being trusted or passed to stat.
secure_node() { return 0; }
ln -s absent-target "$FIXTURE/dangling"
! trusted "$FIXTURE/dangling" 2>"$TMP/errors" || exit 43
[ ! -s "$TMP/errors" ] || exit 44
printf passed
''')
        self.assertEqual(output, 'passed')

    def test_busybox_ps_fallback_terminates_descendants(self):
        output = self.run_shell('''
# Simulate BusyBox rejecting the first format while using the host's ps
# only inside the successful fallback fixture.
ps() {
 printf '%s\\n' "$*" >>"$TMP/ps-calls"
 if [ "$1" = -axo ]; then
  printf 'unsupported ps option\\n' >&2
  return 1
 fi
 [ "$1" = -o ] && [ "$2" = pid=,ppid= ] || return 2
 command ps -axo pid=,ppid= 2>/dev/null || command ps -o pid=,ppid= 2>/dev/null
}
( sleep 120 & printf '%s\\n' "$!" >"$TMP/child.pid"; wait ) &
parent=$!
while [ ! -s "$TMP/child.pid" ]; do sleep 1; done
child=$(cat "$TMP/child.pid")
kill_tree "$parent" 2>"$TMP/errors"
wait "$parent" 2>/dev/null || :
! grep -q unsupported "$TMP/errors" || exit 45
grep -q '^-o pid=,ppid=$' "$TMP/ps-calls" || exit 46
state=$( (command ps -axo pid=,stat= 2>/dev/null || command ps -o pid=,stat= 2>/dev/null) |
 awk -v child="$child" '$1==child {print $2}')
case $state in ''|*Z*) ;; *) kill -KILL "$child"; exit 47;; esac
# Both unsupported formats also fail quietly and still terminate the root.
ps() { printf unsupported >&2; return 1; }
kill() { printf '%s\\n' "$*" >>"$TMP/kill-calls"; }
kill_tree 999999 2>"$TMP/errors"
[ ! -s "$TMP/errors" ] || exit 48
grep -q -- '-KILL 999999' "$TMP/kill-calls" || exit 49
printf passed
''', timeout=10)
        self.assertEqual(output, 'passed')

    def test_json_arbitrary_bytes(self):
        output = self.run_shell("printf '\"'; printf '\\377\\n\\001\\\\\"' | jstr; printf '\"'")
        self.assertEqual(json.loads(output), '\xff\n\x01\\"')

    def test_literal_linux_homes(self):
        output = self.run_shell('''
OS=Linux
awk() { printf '%s\\n' '/home/name with spaces' '/home/name*[?]'; }
record() { printf '<%s>\\n' "$@"; }
with_homes record
''')
        self.assertEqual(output, '</home/name with spaces>\n</home/name*[?]>\n')

    def test_literal_mac_homes(self):
        # Substitute only the platform's fixed home root with the private fixture.
        homes = block('with_homes() {', '\nssh_keys()').replace('/var/root', '"$FIXTURE/root"').replace('/Users/', '"$FIXTURE"/')
        output = self.run_shell('''
OS=Darwin
mkdir "$FIXTURE/root" "$FIXTURE/name with spaces" "$FIXTURE/name*[?]" "$FIXTURE/Shared"
''' + homes + '\nrecord() { printf \'<%s>\\n\' "${1##*/}"; }\nwith_homes record\n')
        self.assertIn('<name with spaces>\n', output)
        self.assertIn('<name*[?]>\n', output)
        self.assertNotIn('<Shared>', output)

    def test_path_bytes_and_inventory(self):
        helper = block('cat >"$TMP/path-record"', '\ntailscale_exposure()')
        output = self.run_shell(helper + '''
f="$FIXTURE/$(printf 'new\\nline.env')"
printf harmless >"$f"
"$TMP/path-record" unit "$f"
# Linux permits arbitrary filename bytes; APFS only permits the byte-encoding
# control, so do not attempt a filesystem write APFS will reject.
if [ "$OS" = Linux ]; then
 f="$FIXTURE/$(printf 'invalid\\377.env')"
 printf harmless >"$f"
 "$TMP/path-record" unit "$f"
else
 path_evidence "$(printf 'invalid\\377.env')"
 printf '\\n'
fi
''')
        records = output.splitlines()
        encoded = records[0].split('path-hex:', 1)[1].split(' ', 1)[0]
        self.assertTrue(bytes.fromhex(encoded).endswith(b'/new\nline.env'))
        encoded_invalid = records[1].split('path-hex:', 1)[1].split(' ', 1)[0]
        self.assertTrue(bytes.fromhex(encoded_invalid).endswith(b'invalid\xff.env'))
        self.assertEqual(len(records), 2)
        self.assertIn('sha256', records[0])

    def test_no_acl_reader_mode_mask_positive_control(self):
        output = self.run_shell('''
OS=Linux
stat_owner() { printf '0\\n'; }
have() { return 1; }
printf '#!/bin/sh\\n' >"$FIXTURE/tool"
chmod 755 "$FIXTURE/tool"
secure_node "$FIXTURE/tool" || exit 21
chmod 775 "$FIXTURE/tool"
! secure_node "$FIXTURE/tool" || exit 22
printf passed
''')
        self.assertEqual(output, 'passed')

    def test_named_acl_grants(self):
        output = self.run_shell('''
OS=Linux
stat_owner() { printf '0\\n'; }
have() { [ "$1" = getfacl ]; }
getfacl() { printf 'user::rwx\\ngroup::r-x\\nother::r-x\\nuser:12345:%s\\nmask::rwx\\n' "$ACL_RIGHTS"; }
printf '#!/bin/sh\\n' >"$FIXTURE/tool"
chmod 755 "$FIXTURE/tool"
ACL_RIGHTS=r-x
secure_node "$FIXTURE/tool" || exit 23
ACL_RIGHTS=rwx
! secure_node "$FIXTURE/tool" || exit 24
printf passed
''')
        self.assertEqual(output, 'passed')

    def test_symlink_resolution_and_permissions(self):
        # Ownership is simulated only within this unprivileged fixture. Actual
        # mode/ACL checks run there; ancestors outside it are the trusted root.
        body = block('secure_node() {', '\nstat_owner()').replace('secure_node() {', 'real_secure_node() {')
        output = self.run_shell(body + '''
stat_owner() { printf '0\\n'; }
getfacl() { printf 'user::rwx\\ngroup::r-x\\nother::r-x\\n'; }
secure_node() {
 case $1 in "$FIXTURE"/*|"$FIXTURE") real_secure_node "$1";; *) return 0;; esac
}
mkdir "$FIXTURE/safe"
printf '#!/bin/sh\\nexit 0\\n' >"$FIXTURE/safe/tool"
chmod 755 "$FIXTURE/safe/tool"
ln -s safe/tool "$FIXTURE/link"
ln -s link "$FIXTURE/chain"
[ "$(trusted "$FIXTURE/chain")" = "$FIXTURE/safe/tool" ] || exit 11
chmod 777 "$FIXTURE/safe/tool"
! trusted "$FIXTURE/chain" || exit 12
chmod 755 "$FIXTURE/safe/tool"
chmod 777 "$FIXTURE/safe"
! trusted "$FIXTURE/chain" || exit 13
chmod 755 "$FIXTURE/safe"
ln -s chain "$FIXTURE/loop"
ln -s loop "$FIXTURE/cycle"
# Replace the first link in the loop without deleting a filesystem object.
ln -s cycle "$FIXTURE/safe/cycle"
ln -s ../safe/cycle "$FIXTURE/safe/recursive"
! trusted "$FIXTURE/safe/recursive" || exit 14
printf passed
''')
        self.assertIn('passed', output)

    def test_failure_large_output_and_timeout(self):
        output = self.run_shell('''
fail() { printf partial; return 7; }
large() { yes flood; }
hang() { sleep 120 & printf '%s\\n' "$!" >"$TMP/hang-child"; wait; }
section failure fail
section large large
section hanging hang
child=$(cat "$TMP/hang-child")
# A killed child may briefly remain as a zombie while init reaps it.
state=$( (command ps -axo pid=,stat= 2>/dev/null || command ps -o pid=,stat= 2>/dev/null) |
 awk -v child="$child" '$1==child {print $2}')
case $state in ''|*Z*) ;; *) exit 31;; esac
cat "$TMP/failure" "$TMP/large" "$TMP/hanging"
''', timeout=40)
        self.assertIn('[collector: failure exit=7]', output)
        self.assertIn('[collector: truncated]', output)
        self.assertIn('[collector: timeout]', output)
        self.assertLess(len(output), 17000)

    def test_linux_mode_print_assembly_with_harmless_sections(self):
        funcs = ['identity', 'accounts', 'ssh', 'listening', 'persistence', 'posture',
                 'updates', 'exposure', 'containers', 'packages', 'lynis']
        overrides = '\n'.join('linux_' + name + '() { printf \'fixture %s\\n\' "' + name + '"; }' for name in funcs)
        overrides += '\ncredential_files() { :; }\nlinux_loose_files() { :; }\ntailscale_peers() { printf fixture; }\nwith_homes() { "$1" /fixture; }\n'
        main = SOURCE[SOURCE.index('if [ "$OS" = Darwin ]; then\n\tsection identity'):]
        output = self.run_shell('OS=Linux\nVERSION=1\n' + overrides + '\nset -- --print\n' + main)
        report = json.loads(output)
        self.assertEqual(report['os'], 'Linux')
        self.assertEqual(len(report['sections']), 14)
        self.assertIn('fixture identity', report['sections']['identity'])
        self.assertLess(len(output.encode()), 2 * 1024 * 1024)


if __name__ == '__main__':
    unittest.main()
