#!/usr/bin/env python3
import subprocess
import re

def run(params=None):
    if params is None:
        params = {}

    check_known_vulnerable = params.get('check_known_vulnerable_packages', True)
    known_vulnerable = params.get('vulnerable_packages', [
        'telnet', 'rsh-client', 'rsh-server', 'talk', 'ntalk',
        'xinetd', 'inetd', 'nis', 'yp-tools', 'tftp', 'atftpd',
        'tftpd', 'tftpd-hpa', 'rpcbind'
    ])
    findings = []
    status = 'pass'

    # Get installed packages (apt/dpkg)
    installed = []
    try:
        result = subprocess.run(
            ['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Status}\n'],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            parts = line.strip().split('\t')
            if len(parts) >= 3 and 'installed' in parts[2]:
                installed.append({'name': parts[0], 'version': parts[1]})
        findings.append(f"INFO: {len(installed)} packages installed (dpkg)")
    except FileNotFoundError:
        # Try rpm
        try:
            result = subprocess.run(['rpm', '-qa', '--queryformat', '%{NAME}\t%{VERSION}\n'],
                                    capture_output=True, text=True)
            for line in result.stdout.splitlines():
                parts = line.strip().split('\t')
                if len(parts) >= 1:
                    installed.append({'name': parts[0], 'version': parts[1] if len(parts) > 1 else 'unknown'})
            findings.append(f"INFO: {len(installed)} packages installed (rpm)")
        except FileNotFoundError:
            findings.append("WARN: No package manager (dpkg/rpm) found")
            return {'test_name': 'Installed Packages Check', 'status': 'warn', 'findings': findings}

    print(f"[*] Checking {len(installed)} installed packages")

    # Check for known dangerous packages
    if check_known_vulnerable:
        installed_names = {p['name'] for p in installed}
        for bad_pkg in known_vulnerable:
            if bad_pkg in installed_names:
                findings.append(f"WARN: Potentially dangerous package installed: {bad_pkg}")
                if status == 'pass':
                    status = 'warn'

    # Check for development tools that shouldn't be on production
    dev_tools = ['gcc', 'g++', 'build-essential', 'gdb', 'strace', 'ltrace', 'make']
    installed_names = {p['name'] for p in installed}
    found_dev = [t for t in dev_tools if t in installed_names]
    if found_dev:
        findings.append(f"INFO: Development tools installed (review if production): {', '.join(found_dev)}")

    # Check if debsecan or similar is available
    try:
        result = subprocess.run(['debsecan', '--suite', 'bullseye', '--only-fixed'],
                                capture_output=True, text=True, timeout=30)
        vulns = [l for l in result.stdout.splitlines() if l.strip()]
        if vulns:
            findings.append(f"FAIL: {len(vulns)} fixed-but-unpatched CVE(s) found via debsecan")
            status = 'fail'
            for v in vulns[:10]:
                findings.append(f"  {v}")
        else:
            findings.append("PASS: No known unpatched CVEs via debsecan")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        findings.append("INFO: debsecan not available (install for CVE scanning)")

    if status == 'pass':
        findings.append("PASS: No dangerous packages found")

    return {'test_name': 'Installed Packages Check', 'status': status, 'package_count': len(installed), 'findings': findings}


if __name__ == "__main__":
    print(run())
