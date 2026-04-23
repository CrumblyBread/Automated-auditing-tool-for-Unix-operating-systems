#!/usr/bin/env python3
import subprocess
import shlex

def _sh(cmd: str, timeout: int | None = None):
    return subprocess.run(["sh", "-lc", cmd], capture_output=True, text=True, timeout=timeout)

def _cat(path: str):
    r = _sh(f"cat {shlex.quote(path)}")
    if r.returncode != 0:
        raise RuntimeError((r.stderr or "").strip() or f"Failed to read {path}")
    return r.stdout

def _list_dir(path: str):
    r = _sh(f"ls -1A {shlex.quote(path)} 2>/dev/null")
    if r.returncode != 0:
        return []
    return [l.strip() for l in r.stdout.splitlines() if l.strip()]

def run(params=None):
    if params is None:
        params = {}

    check_uid0 = params.get('check_uid0_users', True)
    check_no_password = params.get('check_no_password', True)
    check_shell = params.get('check_login_shell', True)
    allowed_uid0 = params.get('allowed_uid0_users', ['root'])
    check_sudoers = params.get('check_sudoers', True)
    findings = []
    status = 'pass'

    # --- UID 0 accounts ---
    if check_uid0:
        uid0_users = []
        try:
            r = _sh("getent passwd")
            if r.returncode != 0:
                raise RuntimeError((r.stderr or "").strip() or "getent passwd failed")
            for line in r.stdout.splitlines():
                parts = line.strip().split(":")
                if len(parts) >= 3 and parts[2].isdigit() and int(parts[2]) == 0:
                    uid0_users.append(parts[0])
            unexpected_uid0 = [u for u in uid0_users if u not in allowed_uid0]
            if unexpected_uid0:
                findings.append(f"CRITICAL: Unexpected UID 0 accounts: {', '.join(unexpected_uid0)}")
                status = 'critical'
            else:
                findings.append(f"PASS: Only expected UID 0 accounts found: {', '.join(uid0_users)}")
        except Exception as e:
            findings.append(f"ERROR: Could not enumerate UID 0 accounts: {e}")

    # --- Accounts with no password (shadow) ---
    if check_no_password:
        try:
            shadow = _cat("/etc/shadow")
            for line in shadow.splitlines():
                parts = line.strip().split(':')
                if len(parts) >= 2:
                    username = parts[0]
                    password_field = parts[1]
                    if password_field == '':
                        findings.append(f"CRITICAL: User '{username}' has no password set")
                        status = 'critical'
                    elif password_field == '!!' or password_field == '!':
                        findings.append(f"INFO: User '{username}' is locked (no login possible)")
            if not any('no password' in f for f in findings):
                findings.append("PASS: No accounts found with empty passwords")
        except Exception as e:
            msg = str(e).lower()
            if ("permission denied" in msg):
                findings.append("INFO: Cannot read /etc/shadow (need root)")
            elif ("no such file" in msg) or ("not found" in msg):
                findings.append("WARN: /etc/shadow not found")
            else:
                findings.append(f"INFO: Could not read /etc/shadow: {e}")

    # --- Login shells for service accounts ---
    if check_shell:
        non_login_shells = ['/usr/sbin/nologin', '/bin/false', '/sbin/nologin', '/bin/nologin']
        service_with_shell = []
        try:
            r = _sh("getent passwd")
            if r.returncode != 0:
                raise RuntimeError((r.stderr or "").strip() or "getent passwd failed")
            for line in r.stdout.splitlines():
                parts = line.strip().split(":")
                if len(parts) < 7:
                    continue
                user = parts[0]
                uid_s = parts[2]
                shell = parts[6]
                if uid_s.isdigit():
                    uid = int(uid_s)
                    if 0 < uid < 1000 and shell not in non_login_shells:
                        service_with_shell.append(f"{user} (uid={uid}, shell={shell})")
            if service_with_shell:
                for u in service_with_shell:
                    findings.append(f"WARN: Service account with login shell: {u}")
                if status == 'pass':
                    status = 'warn'
            else:
                findings.append("PASS: All service accounts have non-login shells")
        except Exception as e:
            findings.append(f"ERROR: Could not check service account shells: {e}")

    # --- Sudoers ---
    if check_sudoers:
        try:
            result = subprocess.run(['getent', 'group', 'sudo'], capture_output=True, text=True)
            sudo_group = result.stdout.strip().split(':')[-1]
            sudo_members = [m for m in sudo_group.split(',') if m]
            findings.append(f"INFO: sudo group members: {', '.join(sudo_members) if sudo_members else 'none'}")

            # Check for NOPASSWD in sudoers
            sudoers_files = ['/etc/sudoers']
            sudoers_dir = '/etc/sudoers.d'
            for f in _list_dir(sudoers_dir):
                sudoers_files.append(f"{sudoers_dir.rstrip('/')}/{f}")

            for sf in sudoers_files:
                try:
                    content = _cat(sf)
                    for line in content.splitlines():
                        if 'NOPASSWD' in line and not line.strip().startswith('#'):
                            findings.append(f"WARN: NOPASSWD entry in {sf}: {line.strip()}")
                            if status == 'pass':
                                status = 'warn'
                except Exception:
                    findings.append(f"INFO: Cannot read {sf} (need root)")

        except Exception as e:
            findings.append(f"ERROR: Could not check sudoers: {e}")

    # --- Check for duplicate UIDs ---
    try:
        uids = {}
        r = _sh("getent passwd")
        if r.returncode != 0:
            raise RuntimeError((r.stderr or "").strip() or "getent passwd failed")
        for line in r.stdout.splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 3 and parts[2].isdigit():
                uid = int(parts[2])
                uids.setdefault(uid, []).append(parts[0])
        for uid, users in uids.items():
            if len(users) > 1 and uid != 65534:  # 65534 is nobody
                findings.append(f"WARN: Duplicate UID {uid} shared by: {', '.join(users)}")
                if status == 'pass':
                    status = 'warn'
    except Exception as e:
        findings.append(f"ERROR: Could not check for duplicate UIDs: {e}")

    return {'test_name': 'User Accounts Audit', 'status': status, 'findings': findings}


if __name__ == "__main__":
    print(run())
