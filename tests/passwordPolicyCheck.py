#!/usr/bin/env python3
import subprocess
import os
import re

def run(params=None):
    if params is None:
        params = {}

    min_length = params.get('min_password_length', 12)
    check_complexity = params.get('check_complexity', True)
    check_expiry = params.get('check_expiry', True)
    max_days = params.get('max_password_age_days', 90)
    findings = []
    status = 'pass'

    # Check /etc/login.defs
    login_defs = '/etc/login.defs'
    if os.path.isfile(login_defs):
        try:
            with open(login_defs) as f:
                content = f.read()

            # PASS_MIN_LEN
            m = re.search(r'^\s*PASS_MIN_LEN\s+(\d+)', content, re.MULTILINE)
            if m:
                val = int(m.group(1))
                if val >= min_length:
                    findings.append(f"PASS: PASS_MIN_LEN is {val} (required: {min_length})")
                else:
                    findings.append(f"FAIL: PASS_MIN_LEN is {val} (required: {min_length})")
                    status = 'fail'
            else:
                findings.append("WARN: PASS_MIN_LEN not set in /etc/login.defs")
                if status == 'pass':
                    status = 'warn'

            # PASS_MAX_DAYS
            if check_expiry:
                m = re.search(r'^\s*PASS_MAX_DAYS\s+(\d+)', content, re.MULTILINE)
                if m:
                    val = int(m.group(1))
                    if val <= max_days:
                        findings.append(f"PASS: PASS_MAX_DAYS is {val} (max allowed: {max_days})")
                    else:
                        findings.append(f"FAIL: PASS_MAX_DAYS is {val} (max allowed: {max_days})")
                        status = 'fail'
                else:
                    findings.append("WARN: PASS_MAX_DAYS not set in /etc/login.defs")
                    if status == 'pass':
                        status = 'warn'

            # PASS_MIN_DAYS
            m = re.search(r'^\s*PASS_MIN_DAYS\s+(\d+)', content, re.MULTILINE)
            if m:
                val = int(m.group(1))
                findings.append(f"INFO: PASS_MIN_DAYS is {val}")

        except Exception as e:
            findings.append(f"ERROR: Could not read {login_defs}: {e}")
    else:
        findings.append(f"WARN: {login_defs} not found")
        if status == 'pass':
            status = 'warn'

    # Check PAM pwquality / cracklib
    if check_complexity:
        pwquality_conf = '/etc/security/pwquality.conf'
        if os.path.isfile(pwquality_conf):
            with open(pwquality_conf) as f:
                pq = f.read()
            findings.append("INFO: pwquality.conf found (complexity enforcement available)")
            m = re.search(r'^\s*minlen\s*=\s*(\d+)', pq, re.MULTILINE)
            if m:
                val = int(m.group(1))
                if val >= min_length:
                    findings.append(f"PASS: pwquality minlen = {val}")
                else:
                    findings.append(f"FAIL: pwquality minlen = {val} (required: {min_length})")
                    status = 'fail'
            pam_pam = '/etc/pam.d/common-password'
            if os.path.isfile(pam_pam):
                with open(pam_pam) as f:
                    pam_content = f.read()
                if 'pwquality' in pam_content or 'cracklib' in pam_content:
                    findings.append("PASS: PAM password complexity module is active")
                else:
                    findings.append("WARN: No password complexity module found in PAM common-password")
                    if status == 'pass':
                        status = 'warn'
        else:
            findings.append("WARN: /etc/security/pwquality.conf not found — password complexity may not be enforced")
            if status == 'pass':
                status = 'warn'

    # Check for accounts with empty passwords
    try:
        result = subprocess.run(['awk', '-F:', '($2 == "" ) {print $1}', '/etc/shadow'], capture_output=True, text=True)
        empty_pass_users = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        if empty_pass_users:
            findings.append(f"CRITICAL: Users with empty passwords: {', '.join(empty_pass_users)}")
            status = 'critical'
        else:
            findings.append("PASS: No accounts with empty passwords found")
    except Exception as e:
        findings.append(f"INFO: Could not check for empty passwords (may need root): {e}")

    return {'test_name': 'Password Policy Check', 'status': status, 'findings': findings}


if __name__ == "__main__":
    print(run())
