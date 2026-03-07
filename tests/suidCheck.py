#!/usr/bin/env python3
import subprocess
import os

def run(params=None):
    if params is None:
        params = {}

    scan_paths = params.get('scan_paths', ['/usr', '/bin', '/sbin', '/usr/bin', '/usr/sbin'])
    known_suid = params.get('known_suid_whitelist', [
        '/usr/bin/sudo', '/usr/bin/su', '/usr/bin/passwd', '/usr/bin/gpasswd',
        '/usr/bin/chfn', '/usr/bin/chsh', '/usr/bin/newgrp', '/usr/bin/pkexec',
        '/usr/bin/mount', '/usr/bin/umount', '/bin/mount', '/bin/umount',
        '/bin/su', '/bin/ping', '/usr/bin/ping', '/usr/sbin/pppd',
        '/usr/lib/openssh/ssh-keysign', '/usr/lib/dbus-1.0/dbus-daemon-launch-helper'
    ])
    findings = []
    status = 'pass'
    found_suid = []
    found_sgid = []

    print(f"[*] Scanning for SUID/SGID files in: {scan_paths}")

    try:
        # Build find command
        path_args = scan_paths
        cmd = ['find'] + path_args + ['-perm', '/4000', '-o', '-perm', '/2000']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        for line in result.stdout.splitlines():
            path = line.strip()
            if not path:
                continue
            try:
                st = os.stat(path)
                mode = oct(st.st_mode)
                if '4' in mode[-4] or mode[-4] == '6' or mode[-4] == '7':
                    found_suid.append(path)
                else:
                    found_sgid.append(path)
            except Exception:
                found_suid.append(path)  # assume SUID if can't stat

        print(f"[*] Found {len(found_suid)} SUID and {len(found_sgid)} SGID files")

        for f in found_suid:
            if f in known_suid:
                findings.append(f"INFO: Known SUID binary: {f}")
            else:
                findings.append(f"WARN: Unknown SUID binary found: {f}")
                if status == 'pass':
                    status = 'warn'

        for f in found_sgid:
            findings.append(f"INFO: SGID file: {f}")

    except subprocess.TimeoutExpired:
        findings.append("ERROR: find command timed out")
        status = 'error'
    except Exception as e:
        findings.append(f"ERROR: {e}")
        status = 'error'

    findings.insert(0, f"INFO: {len(found_suid)} SUID and {len(found_sgid)} SGID files found")

    return {
        'test_name': 'SUID/SGID Files Check',
        'status': status,
        'suid_count': len(found_suid),
        'sgid_count': len(found_sgid),
        'findings': findings
    }


if __name__ == "__main__":
    print(run())
