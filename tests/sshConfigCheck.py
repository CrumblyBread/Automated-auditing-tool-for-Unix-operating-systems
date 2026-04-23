#!/usr/bin/env python3
import re
import subprocess
import shlex

def run(params=None):
    if params is None:
        params = {}

    sshd_config_path = params.get('sshd_config', '/etc/ssh/sshd_config')
    allow_root_login = params.get('allow_root_login', False)
    allow_password_auth = params.get('allow_password_auth', False)
    require_protocol2 = params.get('require_protocol2', True)
    max_auth_tries = params.get('max_auth_tries', 4)
    findings = []
    status = 'pass'

    try:
        # Use cat so it works when subprocess.run is SSH-redirected.
        result = subprocess.run(
            ["sh", "-lc", f"cat {shlex.quote(sshd_config_path)}"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            err = (result.stderr or "").strip()
            err_l = err.lower()
            if ("no such file" in err_l) or ("not found" in err_l):
                findings.append(f"WARN: sshd_config not found at {sshd_config_path}")
                return {'test_name': 'SSH Configuration Check', 'status': 'warn', 'findings': findings}
            if "permission denied" in err_l:
                findings.append(f"ERROR: Permission denied reading {sshd_config_path} (run as root)")
                return {'test_name': 'SSH Configuration Check', 'status': 'error', 'findings': findings}
            findings.append(f"ERROR: Could not read {sshd_config_path}: {err or 'unknown error'}")
            return {'test_name': 'SSH Configuration Check', 'status': 'error', 'findings': findings}
        content = result.stdout
    except Exception as e:
        findings.append(f"ERROR: Could not read {sshd_config_path}: {e}")
        return {'test_name': 'SSH Configuration Check', 'status': 'error', 'findings': findings}

    def get_setting(key):
        m = re.search(rf'^\s*{key}\s+(.+)', content, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip() if m else None

    # PermitRootLogin
    val = get_setting('PermitRootLogin')
    if val:
        if val.lower() in ('no', 'prohibit-password', 'forced-commands-only'):
            findings.append(f"PASS: PermitRootLogin = {val}")
        elif val.lower() == 'yes' and not allow_root_login:
            findings.append(f"FAIL: PermitRootLogin = yes (root SSH login is allowed)")
            status = 'fail'
        else:
            findings.append(f"INFO: PermitRootLogin = {val}")
    else:
        findings.append("WARN: PermitRootLogin not explicitly set (defaults may allow root)")
        if status == 'pass':
            status = 'warn'

    # PasswordAuthentication
    val = get_setting('PasswordAuthentication')
    if val:
        if val.lower() == 'no':
            findings.append("PASS: PasswordAuthentication = no (key-based only)")
        elif val.lower() == 'yes' and not allow_password_auth:
            findings.append("WARN: PasswordAuthentication = yes (password login allowed)")
            if status == 'pass':
                status = 'warn'
    else:
        findings.append("WARN: PasswordAuthentication not set")
        if status == 'pass':
            status = 'warn'

    # Protocol
    val = get_setting('Protocol')
    if val:
        if val.strip() == '2':
            findings.append("PASS: Protocol = 2")
        else:
            findings.append(f"FAIL: Protocol = {val} (should be 2)")
            if require_protocol2:
                status = 'fail'
    else:
        findings.append("INFO: Protocol not explicitly set (SSH2 is default in modern OpenSSH)")

    # MaxAuthTries
    val = get_setting('MaxAuthTries')
    if val:
        try:
            v = int(val)
            if v <= max_auth_tries:
                findings.append(f"PASS: MaxAuthTries = {v}")
            else:
                findings.append(f"WARN: MaxAuthTries = {v} (recommended: {max_auth_tries})")
                if status == 'pass':
                    status = 'warn'
        except ValueError:
            pass
    else:
        findings.append(f"WARN: MaxAuthTries not set (default is 6)")
        if status == 'pass':
            status = 'warn'

    # X11Forwarding
    val = get_setting('X11Forwarding')
    if val and val.lower() == 'yes':
        findings.append("WARN: X11Forwarding = yes (consider disabling if not needed)")
        if status == 'pass':
            status = 'warn'
    else:
        findings.append("PASS: X11Forwarding is not enabled")

    # PermitEmptyPasswords
    val = get_setting('PermitEmptyPasswords')
    if val and val.lower() == 'yes':
        findings.append("FAIL: PermitEmptyPasswords = yes — critical risk!")
        status = 'fail'
    else:
        findings.append("PASS: PermitEmptyPasswords is not enabled")

    # LoginGraceTime
    val = get_setting('LoginGraceTime')
    if val:
        findings.append(f"INFO: LoginGraceTime = {val}")
    
    # AllowTcpForwarding
    val = get_setting('AllowTcpForwarding')
    if val and val.lower() == 'yes':
        findings.append("WARN: AllowTcpForwarding = yes (consider disabling if not needed)")

    # UsePAM
    val = get_setting('UsePAM')
    if val and val.lower() == 'yes':
        findings.append("PASS: UsePAM = yes")

    return {'test_name': 'SSH Configuration Check', 'status': status, 'findings': findings}


if __name__ == "__main__":
    print(run())
