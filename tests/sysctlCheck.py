#!/usr/bin/env python3
import subprocess

def run(params=None):
    if params is None:
        params = {}

    strict_mode = params.get('strict_mode', False)
    findings = []
    status = 'pass'

    # Expected secure values: key -> (expected_value, description, is_critical)
    checks = {
        'kernel.randomize_va_space':         ('2',  'ASLR fully enabled',                 True),
        'net.ipv4.ip_forward':               ('0',  'IP forwarding disabled',              False),
        'net.ipv4.conf.all.send_redirects':  ('0',  'ICMP redirects disabled (send)',      False),
        'net.ipv4.conf.default.send_redirects': ('0', 'ICMP redirects disabled (default)', False),
        'net.ipv4.conf.all.accept_redirects':('0',  'ICMP redirects not accepted',         False),
        'net.ipv4.conf.all.accept_source_route': ('0', 'Source routing disabled',         True),
        'net.ipv4.conf.all.log_martians':    ('1',  'Martian packet logging enabled',      False),
        'net.ipv4.tcp_syncookies':           ('1',  'SYN flood protection enabled',        True),
        'net.ipv4.icmp_echo_ignore_broadcasts': ('1', 'ICMP broadcast echo disabled',     False),
        'net.ipv4.icmp_ignore_bogus_error_responses': ('1', 'Bogus ICMP error responses ignored', False),
        'kernel.dmesg_restrict':             ('1',  'dmesg restricted to root',            False),
        'kernel.kptr_restrict':              ('2',  'Kernel pointer leak restricted',      False),
        'kernel.sysrq':                      ('0',  'SysRq key disabled',                 False),
        'kernel.core_uses_pid':              ('1',  'Core dumps use PID',                 False),
        'net.ipv6.conf.all.accept_redirects':('0',  'IPv6 ICMP redirects not accepted',   False),
        'net.ipv6.conf.all.accept_ra':       ('0',  'IPv6 router advertisements disabled', False),
        'fs.suid_dumpable':                  ('0',  'SUID core dumps disabled',            True),
        'fs.protected_hardlinks':            ('1',  'Hardlink protection enabled',         True),
        'fs.protected_symlinks':             ('1',  'Symlink protection enabled',          True),
    }

    def get_sysctl(key):
        try:
            result = subprocess.run(['sysctl', '-n', key], capture_output=True, text=True)
            return result.stdout.strip()
        except Exception:
            return None

    for key, (expected, description, is_critical) in checks.items():
        val = get_sysctl(key)
        if val is None:
            findings.append(f"INFO: {key} — not available on this system")
            continue

        if val == expected:
            findings.append(f"PASS: {key} = {val} ({description})")
        else:
            severity = "FAIL" if is_critical or strict_mode else "WARN"
            findings.append(f"{severity}: {key} = {val} (expected {expected}) — {description}")
            if is_critical or strict_mode:
                status = 'fail'
            elif status == 'pass':
                status = 'warn'

    return {'test_name': 'Sysctl Security Parameters Check', 'status': status, 'findings': findings}


if __name__ == "__main__":
    print(run({'strict_mode': False}))
