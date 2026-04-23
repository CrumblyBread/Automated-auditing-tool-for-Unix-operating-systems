#!/usr/bin/env python3
import subprocess
import shlex

def _sh(cmd: str, timeout: int | None = None):
    return subprocess.run(["sh", "-lc", cmd], capture_output=True, text=True, timeout=timeout)

def _is_file(path: str) -> bool:
    r = _sh(f"test -f {shlex.quote(path)}")
    return r.returncode == 0

def _is_dir(path: str) -> bool:
    r = _sh(f"test -d {shlex.quote(path)}")
    return r.returncode == 0

def _file_size(path: str):
    r = _sh(f"stat -c %s {shlex.quote(path)} 2>/dev/null")
    if r.returncode == 0:
        s = (r.stdout or "").strip()
        if s.isdigit():
            return int(s)
    return None

def _list_dir(path: str):
    r = _sh(f"ls -1A {shlex.quote(path)} 2>/dev/null")
    if r.returncode != 0:
        return []
    return [l.strip() for l in r.stdout.splitlines() if l.strip()]

def run(params=None):
    if params is None:
        params = {}

    require_auditd = params.get('require_auditd', True)
    check_log_rotation = params.get('check_log_rotation', True)
    check_syslog = params.get('check_syslog', True)
    findings = []
    status = 'pass'

    auditd_active = False
    try:
        result = subprocess.run(['systemctl', 'is-active', 'auditd'], capture_output=True, text=True)
        if result.stdout.strip() == 'active':
            findings.append("PASS: auditd je aktívny")
            auditd_active = True
        else:
            findings.append(f"WARN: auditd nie je aktívny (status: {result.stdout.strip()})")
            if require_auditd:
                status = 'fail'
            elif status == 'pass':
                status = 'warn'
    except FileNotFoundError:
        findings.append("INFO: systemctl nenájdený, skúšam príkaz service")
        try:
            result = subprocess.run(['service', 'auditd', 'status'], capture_output=True, text=True)
            if 'running' in result.stdout.lower():
                findings.append("PASS: auditd je spustený")
                auditd_active = True
            else:
                findings.append("WARN: auditd nevyznává že běží")
                if require_auditd and status == 'pass':
                    status = 'warn'
        except Exception:
            findings.append("WARN: Nedá se zistiť stav auditd")

    if auditd_active:
        try:
            result = subprocess.run(['auditctl', '-l'], capture_output=True, text=True)
            rules = [l for l in result.stdout.splitlines() if l.strip() and 'No rules' not in l]
            if rules:
                findings.append(f"PASS: {len(rules)} audit rule(s) configured")
            else:
                findings.append("WARN: auditd is running but no rules configured")
                if status == 'pass':
                    status = 'warn'

            important_rules = ['-w /etc/passwd', '-w /etc/shadow', '-w /etc/sudoers', '-w /var/log/auth.log']
            combined_rules = '\n'.join(result.stdout.splitlines())
            for rule in important_rules:
                if rule in combined_rules:
                    findings.append(f"PASS: Audit rule present: {rule}")
                else:
                    findings.append(f"INFO: Audit rule not found: {rule}")
        except FileNotFoundError:
            findings.append("INFO: auditctl not available")

    if check_syslog:
        syslog_services = ['rsyslog', 'syslog', 'systemd-journald', 'syslog-ng']
        found_logger = False
        for svc in syslog_services:
            try:
                result = subprocess.run(['systemctl', 'is-active', svc], capture_output=True, text=True)
                if result.stdout.strip() == 'active':
                    findings.append(f"PASS: {svc} is active")
                    found_logger = True
            except Exception:
                pass
        if not found_logger:
            findings.append("WARN: No syslog service detected (rsyslog, syslog-ng, journald)")
            if status == 'pass':
                status = 'warn'

    log_files = ['/var/log/auth.log', '/var/log/syslog', '/var/log/messages', '/var/log/kern.log']
    for lf in log_files:
        if _is_file(lf):
            try:
                size = _file_size(lf)
                if size is None:
                    findings.append(f"INFO: Log file present: {lf}")
                else:
                    findings.append(f"INFO: Log file present: {lf} ({size} bytes)")
            except Exception:
                findings.append(f"INFO: Log file present: {lf}")

    if check_log_rotation:
        logrotate_conf = '/etc/logrotate.conf'
        logrotate_d = '/etc/logrotate.d'
        if _is_file(logrotate_conf):
            findings.append("PASS: logrotate.conf present")
        else:
            findings.append("WARN: /etc/logrotate.conf not found")
            if status == 'pass':
                status = 'warn'
        if _is_dir(logrotate_d):
            count = len(_list_dir(logrotate_d))
            findings.append(f"INFO: {count} logrotate.d config(s) found")

    return {'test_name': 'Audit Logging Configuration', 'status': status, 'findings': findings}


if __name__ == "__main__":
    print(run())
