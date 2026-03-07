#!/usr/bin/env python3
import subprocess
import os
import pwd
import grp

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
            for entry in pwd.getpwall():
                if entry.pw_uid == 0:
                    uid0_users.append(entry.pw_name)
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
            with open('/etc/shadow') as f:
                for line in f:
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
        except PermissionError:
            findings.append("INFO: Cannot read /etc/shadow (need root)")
        except FileNotFoundError:
            findings.append("WARN: /etc/shadow not found")

    # --- Login shells for service accounts ---
    if check_shell:
        non_login_shells = ['/usr/sbin/nologin', '/bin/false', '/sbin/nologin', '/bin/nologin']
        service_with_shell = []
        try:
            for entry in pwd.getpwall():
                # Typical service UIDs are 1-999 (excluding root=0)
                if 0 < entry.pw_uid < 1000:
                    if entry.pw_shell not in non_login_shells:
                        service_with_shell.append(f"{entry.pw_name} (uid={entry.pw_uid}, shell={entry.pw_shell})")
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
            if os.path.isdir(sudoers_dir):
                for f in os.listdir(sudoers_dir):
                    sudoers_files.append(os.path.join(sudoers_dir, f))

            for sf in sudoers_files:
                try:
                    with open(sf) as f:
                        for line in f:
                            if 'NOPASSWD' in line and not line.strip().startswith('#'):
                                findings.append(f"WARN: NOPASSWD entry in {sf}: {line.strip()}")
                                if status == 'pass':
                                    status = 'warn'
                except (PermissionError, FileNotFoundError):
                    findings.append(f"INFO: Cannot read {sf} (need root)")

        except Exception as e:
            findings.append(f"ERROR: Could not check sudoers: {e}")

    # --- Check for duplicate UIDs ---
    try:
        uids = {}
        for entry in pwd.getpwall():
            uids.setdefault(entry.pw_uid, []).append(entry.pw_name)
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
