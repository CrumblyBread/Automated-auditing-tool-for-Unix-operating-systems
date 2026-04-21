#!/usr/bin/env python3
import subprocess

def run(params=None):
    if params is None:
        params = {}

    check_unnecessary = params.get('check_unnecessary_services', True)
    unnecessary_services = params.get('unnecessary_services', [
        'telnet', 'rsh', 'rlogin', 'rexec', 'finger', 'talk', 'ntalk',
        'chargen', 'daytime', 'discard', 'echo', 'time', 'avahi-daemon',
        'cups', 'isc-dhcp-server', 'slapd', 'nfs-server', 'nis',
        'rpcbind', 'snmpd', 'vsftpd', 'proftpd', 'pure-ftpd', 'xinetd'
    ])
    findings = []
    status = 'pass'
    running_services = []

    # Try systemctl
    try:
        result = subprocess.run(
            ['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager', '--no-legend'],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if parts:
                svc = parts[0].replace('.service', '')
                running_services.append(svc)

        print(f"[*] Našiel som {len(running_services)} bežiacich služieb")
        findings.append(f"INFO: {len(running_services)} services currently running")

    except FileNotFoundError:
        # Try service --status-all
        try:
            result = subprocess.run(['service', '--status-all'], capture_output=True, text=True)
            for line in result.stderr.splitlines():
                if '[ + ]' in line:
                    svc = line.strip().split()[-1]
                    running_services.append(svc)
        except FileNotFoundError:
            findings.append("WARN: Could not enumerate running services (no systemctl or service)")
            return {'test_name': 'Running Services Audit', 'status': 'warn', 'findings': findings}

    # Check for unnecessary/dangerous services
    if check_unnecessary:
        for svc in running_services:
            for bad_svc in unnecessary_services:
                if bad_svc in svc:
                    findings.append(f"WARN: Potentially unnecessary service running: {svc}")
                    if status == 'pass':
                        status = 'warn'
                    break

    # Flag unencrypted protocol services specifically
    dangerous = {'telnet': 'Telnet (cleartext remote access)', 'ftp': 'FTP (cleartext file transfer)',
                 'rsh': 'RSH (cleartext remote shell)', 'rlogin': 'Rlogin (cleartext remote login)',
                 'finger': 'Finger (user info disclosure)', 'vnc': 'VNC (check if exposed externally)',
                 'x11': 'X11 service running'}
    for svc in running_services:
        for keyword, desc in dangerous.items():
            if keyword in svc.lower():
                findings.append(f"FAIL: Dangerous service detected: {svc} — {desc}")
                status = 'fail'
                break

    # Check for services listening on 0.0.0.0
    try:
        result = subprocess.run(['ss', '-tlnp'], capture_output=True, text=True)
        any_all_iface = False
        for line in result.stdout.splitlines():
            if '0.0.0.0:' in line or '*:' in line:
                parts = line.split()
                local_addr = [p for p in parts if '0.0.0.0:' in p or '*:' in p]
                for addr in local_addr:
                    port = addr.split(':')[-1]
                    if port not in ('*', ''):
                        findings.append(f"INFO: Service listening on all interfaces — port {port}")
                        any_all_iface = True
        if not any_all_iface:
            findings.append("PASS: No services unexpectedly listening on all interfaces")
    except Exception:
        pass

    if status == 'pass':
        findings.append("PASS: No unnecessary or dangerous services detected")

    return {'test_name': 'Running Services Audit', 'status': status, 'running_count': len(running_services), 'findings': findings}


if __name__ == "__main__":
    print(run())
