#!/usr/bin/env python3
"""Non-root installer exercise: all writes, downloads, and schedulers redirected.

Only the test copy's trust boundary/uid and command PATH are adapted. Production
ancestor checks still run for every component below the temporary test root.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parents[1] / 'install.sh'
TOKEN = 'a' * 64


def run_case(scheduler, attack=None, canaries=False, token_stdin=False, token_prompt=False, canary_user="root", refresh=False):
    with tempfile.TemporaryDirectory(prefix='tattle-installer-') as tmp:
        root = Path(tmp).resolve()
        bin_dir = root / 'bin'
        bin_dir.mkdir(mode=0o755)
        def executable(name, content):
            p = bin_dir / name
            p.write_text('#!/bin/sh\n' + content + '\n')
            p.chmod(0o755)
        os_name = 'Darwin' if scheduler == 'launchd' else 'Linux'
        executable('uname', f'echo {os_name}')
        executable('id', f'if [ "$1" = -u ]; then echo {os.getuid()}; else exec /usr/bin/id "$@"; fi')
        executable('chown', f'test \"$1\" = {os.getuid()} || exit 94; test -f \"$2\" || test -d \"$2\" || exit 95; printf \"%s %s\\n\" \"$1\" \"$2\" >>{root}/chown.log')
        executable('sudo', 'test "$1" = -u || exit 92; shift 2; exec /usr/bin/env "$@"')
        stat_args = "-f '%u %Lp'" if os.uname().sysname == 'Darwin' else "-c '%u %a'"
        canary_fixture = root / 'canary-fixture'
        canary_fixture.write_text(f'''#!/bin/sh
[ "$(/usr/bin/stat {stat_args} "$0")" = "{os.getuid()} 600" ] || exit 93
[ "$(tail -n 1 {root}/chown.log)" = "{os.getuid()} $0" ] || exit 96
printf 'private canary executed\\n' >>{root}/canary-executions
printf '%s\\n' \"$*\" >>{root}/canary-args
''')
        executable('curl', f'FIXTURE={canary_fixture}\n' + '''IS_CANARY=
case "$*" in *canaries.sh*) IS_CANARY=yes;; esac
OUT=
while [ "$#" -gt 0 ]; do
 if [ "$1" = -o ]; then shift; OUT=$1; fi
 shift
done
if [ -n "$IS_CANARY" ]; then cat "$FIXTURE" >"$OUT"; else printf '#!/bin/sh\\nexit 0\\n' >"$OUT"; fi''')
        executable('launchctl', 'exit 0')
        executable('getent', f'echo "root:x:0:0:root:{root}:/bin/sh"')
        executable('dscl', f'echo "NFSHomeDirectory: {root}"')
        executable('getfacl', 'exit 0')
        if scheduler == 'systemd':
            executable('systemctl', 'exit 0')
        if os.uname().sysname == 'Darwin':
            executable('stat', '''if [ "$1" = -c ]; then shift 2; exec /usr/bin/stat -f '%u %Lp' "$@"; fi
exec /usr/bin/stat "$@"''')
        else:
            executable('ls', '''if [ "$1" = -lde ]; then shift; exec /bin/ls -ld "$@"; fi
exec /bin/ls "$@"''')
            executable('stat', '''if [ "$1" = -f ]; then shift 2; exec /usr/bin/stat -c '%u %a' "$@"; fi
exec /usr/bin/stat "$@"''')
        script = SOURCE.read_text()
        script = script.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin', f'PATH={bin_dir}:/usr/sbin:/usr/bin:/sbin:/bin')
        script = script.replace('OWNER_UID=0', f'OWNER_UID={os.getuid()}')
        script = script.replace('__TATTLE_URL__', 'https://example.test')
        script = re.sub(r'/usr/local/libexec/tattle|/private/etc|/etc|/Library/LaunchDaemons|/private/var/log|/var/log', lambda m: str(root) + m.group(), script)
        # Ancestors outside the redirected tree belong to the test runner's
        # environment, not the installer's trust boundary under test.
        ancestors = '|'.join(str(p) for p in root.parents)
        script = script.replace('check_node() {', 'check_node() {\n\tcase "$1" in ' + ancestors + ') return;; esac')
        if scheduler == 'cron':
            script = script.replace('elif command -v systemctl >/dev/null 2>&1; then', 'elif false; then')
        if token_prompt:
            (root / 'token.input').write_text(TOKEN + '\n')
            script = script.replace('>/dev/tty', '>' + str(root / 'prompt-output'))
            script = script.replace('/dev/tty', str(root / 'token.input'))
            executable('stty', "printf '%s\\n' \"$*\" >>" + str(root / 'stty.log'))
        installer = root / 'install.sh'
        installer.write_text(script)
        destination = root / 'usr/local/libexec/tattle'
        outside = root / 'untouched'
        outside.write_text('unchanged')
        if attack:
            destination.mkdir(parents=True, mode=0o755)
            if attack == 'file_symlink':
                (destination / 'tattle-collect').symlink_to(outside)
            elif attack == 'directory_symlink':
                destination.rmdir()
                destination.symlink_to(root / 'bin', target_is_directory=True)
            elif attack == 'writable_directory':
                destination.chmod(0o777)
            elif attack in ('config_symlink', 'scheduler_symlink'):
                target = root / ('etc/tattle/env' if attack == 'config_symlink' else 'etc/systemd/system/tattle.service')
                target.parent.mkdir(parents=True, mode=0o755)
                target.symlink_to(outside)
            elif attack == 'acl_write_grant':
                executable('getfacl', 'echo user:untrusted:rwx')
        command = ['/bin/sh', str(installer), '--prompt-token' if token_prompt else ('--token-stdin' if token_stdin else TOKEN)]
        if not canaries:
            command.append('--no-canaries')
        if refresh:
            command.append('--refresh-canaries')
        env = dict(os.environ, SUDO_USER=canary_user)
        def invoke():
            return subprocess.run(command, env=env, input=TOKEN + '\n' if token_stdin else None,
                                  capture_output=True, text=True, umask=0)
        result = invoke()
        if attack:
            assert result.returncode != 0, (attack, result.stdout, result.stderr)
            assert outside.read_text() == 'unchanged'
        else:
            assert result.returncode == 0, (scheduler, result.stdout, result.stderr)
            assert (destination / 'tattle-collect').stat().st_mode & 0o777 == 0o755
            etc = root / ('private/etc' if scheduler == 'launchd' else 'etc')
            assert (etc / 'tattle/env').stat().st_mode & 0o777 == 0o600
            for p in root.rglob('*'):
                if p.is_dir():
                    assert p.stat().st_mode & 0o022 == 0, str(p)
            if scheduler == 'launchd':
                definition = (root / 'Library/LaunchDaemons/dev.tattle.collect.plist').read_text()
            elif scheduler == 'systemd':
                definition = (etc / 'systemd/system/tattle.service').read_text()
                assert (etc / 'systemd/system/tattle.timer').exists()
            else:
                definition = (etc / 'cron.d/tattle').read_text()
            assert str(destination / 'tattle-collect') in definition
            assert not list(root.rglob('.tattle-install.*'))
            # Updates must also succeed against the files the installer created.
            rerun = invoke()
            assert rerun.returncode == 0, rerun.stderr
            if canaries:
                assert (root / 'canary-executions').read_text().splitlines() == ['private canary executed', 'private canary executed']
                assert (root / 'canary-args').read_text().splitlines() == (['--refresh', '--refresh'] if refresh else ['', ''])
            if token_prompt:
                assert (root / 'stty.log').read_text().splitlines() == ['-echo', 'echo', '-echo', 'echo']
                assert TOKEN not in result.stdout + result.stderr
                assert TOKEN not in ' '.join(command)
        print(f'PASS {scheduler}{" refresh" if refresh else ""}{" token-stdin" if token_stdin else " prompt-token" if token_prompt else ""}: {attack or ("install + update + canaries" if canaries else "install + update")}')


if __name__ == '__main__':
    subprocess.run(['/bin/sh', '-n', str(SOURCE)], check=True)
    print('PASS production shell syntax (token and canary branches)')
    # Production parsing must reject contradictions before privileged install work.
    for flags, extra_env, message in [
        (['--no-canaries', '--refresh-canaries'], {}, 'conflicts with disabled canaries'),
        (['--refresh-canaries'], {'TATTLE_NO_CANARIES': '1'}, 'conflicts with disabled canaries'),
        (['--unknown'], {}, 'unknown option'),
    ]:
        invalid = subprocess.run(['/bin/sh', str(SOURCE), '--token-stdin', *flags],
                                 input=TOKEN + '\n', env=dict(os.environ, **extra_env),
                                 capture_output=True, text=True)
        assert invalid.returncode != 0 and message in invalid.stderr, invalid.stderr
        assert TOKEN not in invalid.stdout + invalid.stderr
    print('PASS production flags fail before install on conflict/unknown options')
    for scheduler in ['launchd', 'systemd', 'cron']:
        run_case(scheduler)
    for attack in ['file_symlink', 'directory_symlink', 'writable_directory', 'config_symlink', 'scheduler_symlink', 'acl_write_grant']:
        run_case('systemd', attack=attack)
    run_case('launchd', canaries=True)
    run_case('systemd', canaries=True)
    run_case('systemd', canaries=True, canary_user='tattletest')
    run_case('systemd', token_stdin=True)
    run_case('systemd', token_prompt=True)
    run_case('launchd', canaries=True, refresh=True)
    run_case('systemd', canaries=True, canary_user='tattletest', token_stdin=True, refresh=True)
    run_case('systemd', canaries=True, token_prompt=True, refresh=True)
