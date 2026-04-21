#!/usr/bin/env python3
import os
import subprocess
import stat

def run(params=None):
    if params is None:
        params = {}

    check_world_writable = params.get('check_world_writable', True)
    check_unowned = params.get('check_unowned', True)
    check_root_cron = params.get('check_root_cron', True)
    findings = []
    status = 'pass'

    cron_dirs = [
        '/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly',
        '/etc/cron.weekly', '/etc/cron.monthly'
    ]
    cron_files = ['/etc/crontab', '/etc/anacrontab']

    all_cron_files = list(cron_files)

    for d in cron_dirs:
        if os.path.isdir(d):
            for fname in os.listdir(d):
                all_cron_files.append(os.path.join(d, fname))

    print(f"[*] Skenujem {len(all_cron_files)} cron súbor(ov)")

    for cf in all_cron_files:
        if not os.path.isfile(cf):
            continue
        try:
            st = os.stat(cf)
            mode = st.st_mode
            perms = stat.S_IMODE(mode)

            if check_world_writable and (mode & stat.S_IWOTH):
                findings.append(f"FAIL: Cron file is world-writable: {cf} ({oct(perms)[2:]})")
                status = 'fail'
            else:
                findings.append(f"PASS: {cf} ({oct(perms)[2:]})")

            if check_unowned and st.st_uid != 0:
                findings.append(f"WARN: Cron file not owned by root: {cf} (uid={st.st_uid})")
                if status == 'pass':
                    status = 'warn'

        except Exception as e:
            findings.append(f"ERROR: Could not stat {cf}: {e}")

    # Check user crontabs
    try:
        spool_dir = '/var/spool/cron/crontabs'
        if os.path.isdir(spool_dir):
            users_with_cron = os.listdir(spool_dir)
            if users_with_cron:
                findings.append(f"INFO: Users with crontabs: {', '.join(users_with_cron)}")
            else:
                findings.append("INFO: No user crontabs found")
        else:
            findings.append("INFO: No crontab spool directory found")
    except PermissionError:
        findings.append("INFO: Cannot read crontab spool (need root)")

    # Check at jobs
    try:
        at_spool = '/var/spool/at'
        if os.path.isdir(at_spool):
            at_jobs = [f for f in os.listdir(at_spool) if not f.startswith('.')]
            if at_jobs:
                findings.append(f"INFO: {len(at_jobs)} pending at job(s) found")
            else:
                findings.append("INFO: No pending at jobs")
    except PermissionError:
        findings.append("INFO: Cannot read at spool (need root)")
    except FileNotFoundError:
        findings.append("INFO: at spool not found")

    # Scan crontab content for suspicious patterns
    suspicious_patterns = ['wget', 'curl', 'bash -i', 'nc ', 'ncat', 'python -c', 'perl -e', '/dev/tcp']
    for cf in all_cron_files:
        if not os.path.isfile(cf):
            continue
        try:
            with open(cf) as f:
                content = f.read()
            for pat in suspicious_patterns:
                if pat in content:
                    findings.append(f"WARN: Suspicious pattern '{pat}' found in {cf}")
                    if status == 'pass':
                        status = 'warn'
        except (PermissionError, UnicodeDecodeError):
            pass

    if not findings:
        findings.append("INFO: No cron files found to audit")

    return {'test_name': 'Cron Jobs Audit', 'status': status, 'findings': findings}


if __name__ == "__main__":
    print(run())
