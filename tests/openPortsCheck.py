#!/usr/bin/env python3
import subprocess
import re

def run(params=None):
    if params is None:
        params = {}

    allowed_ports = params.get('allowed_ports', [22, 80, 443])
    warn_on_unexpected = params.get('warn_on_unexpected', True)
    check_udp = params.get('check_udp', False)
    findings = []
    status = 'pass'
    open_ports = []

    # Try ss first, fallback to netstat
    def parse_listeners(output, proto):
        ports = []
        for line in output.splitlines():
            # Match LISTEN/UNCONN lines
            if 'LISTEN' in line or (check_udp and 'UNCONN' in line):
                parts = line.split()
                for part in parts:
                    m = re.search(r'[:\[](\d+)\]?$', part)
                    if m:
                        try:
                            port = int(m.group(1))
                            ports.append((port, proto, line.strip()))
                        except ValueError:
                            pass
                        break
        return ports

    try:
        cmd = ['ss', '-tlnp'] if not check_udp else ['ss', '-tlunp']
        result = subprocess.run(cmd, capture_output=True, text=True)
        open_ports += parse_listeners(result.stdout, 'TCP')

        if check_udp:
            result_udp = subprocess.run(['ss', '-ulnp'], capture_output=True, text=True)
            open_ports += parse_listeners(result_udp.stdout, 'UDP')

        print(f"[*] Našiel som {len(open_ports)} port(ov) v režime LISTEN")

    except FileNotFoundError:
        try:
            result = subprocess.run(['netstat', '-tlnp'], capture_output=True, text=True)
            open_ports += parse_listeners(result.stdout, 'TCP')
        except FileNotFoundError:
            findings.append("ERROR: Neither ss nor netstat available")
            return {'test_name': 'Open Ports Check', 'status': 'error', 'findings': findings}

    seen = set()
    for port, proto, raw in open_ports:
        if port in seen:
            continue
        seen.add(port)
        if port in allowed_ports:
            findings.append(f"PASS: Port {port}/{proto} is open and in allowed list")
        else:
            msg = f"WARN: Port {port}/{proto} is open but NOT in allowed list"
            findings.append(msg)
            if warn_on_unexpected and status == 'pass':
                status = 'warn'

    if not open_ports:
        findings.append("INFO: No listening TCP ports detected")

    # Highlight sensitive well-known ports
    sensitive = {21: 'FTP', 23: 'Telnet', 25: 'SMTP', 110: 'POP3', 143: 'IMAP',
                 3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB', 6379: 'Redis',
                 11211: 'Memcached', 9200: 'Elasticsearch', 2375: 'Docker (unencrypted)'}
    for port, proto, raw in open_ports:
        if port in sensitive:
            findings.append(f"WARN: Sensitive service port open — {port} ({sensitive[port]})")
            if status == 'pass':
                status = 'warn'

    return {'test_name': 'Open Ports Check', 'status': status, 'open_ports': list(seen), 'findings': findings}


if __name__ == "__main__":
    print(run({'allowed_ports': [22, 80, 443], 'check_udp': False}))
