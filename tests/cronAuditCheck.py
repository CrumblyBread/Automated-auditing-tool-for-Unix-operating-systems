#!/usr/bin/env python3
import subprocess
import stat
import shlex

def _sh(cmd: str, timeout: int | None = None):
    return subprocess.run(["sh", "-lc", cmd], capture_output=True, text=True, timeout=timeout)

def _is_dir(path: str) -> bool:
    return _sh(f"test -d {shlex.quote(path)}").returncode == 0

def _is_file(path: str) -> bool:
    return _sh(f"test -f {shlex.quote(path)}").returncode == 0

def _list_dir(path: str):
    r = _sh(f"ls -1A {shlex.quote(path)} 2>/dev/null")
    if r.returncode != 0:
        return []
    return [l.strip() for l in r.stdout.splitlines() if l.strip()]

def _stat_mode_uid(path: str):
    # Returns (mode_int, uid_int) or (None, None) if stat fails.
    r = _sh(f"stat -c '%a %u' {shlex.quote(path)} 2>/dev/null")
    if r.returncode != 0:
        return (None, None)
    parts = (r.stdout or "").strip().strip("'").split()
    if len(parts) != 2:
        return (None, None)
    mode_s, uid_s = parts
    if not mode_s.isdigit() or not uid_s.isdigit():
        return (None, None)
    return (int(mode_s, 10), int(uid_s, 10))

def _read_file(path: str):
    r = _sh(f"cat {shlex.quote(path)} 2>/dev/null")
    if r.returncode != 0:
        raise RuntimeError((r.stderr or "").strip() or f"Failed to read {path}")
    return r.stdout

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
        if _is_dir(d):
            for fname in _list_dir(d):
                all_cron_files.append(f"{d.rstrip('/')}/{fname}")

    print(f"[*] Skenujem {len(all_cron_files)} cron súbor(ov)")

    for cf in all_cron_files:
        if not _is_file(cf):
            continue
        try:
            perms_octal, uid = _stat_mode_uid(cf)
            if perms_octal is None:
                raise RuntimeError("stat failed")
            # Convert e.g. 644 -> int bits so existing checks work
            perms = int(str(perms_octal), 8)
            mode = perms

            if check_world_writable and (mode & stat.S_IWOTH):
                findings.append(f"FAIL: Cron file is world-writable: {cf} ({oct(perms)[2:]})")
                status = 'fail'
            else:
                findings.append(f"PASS: {cf} ({oct(perms)[2:]})")

            if check_unowned and uid is not None and uid != 0:
                findings.append(f"WARN: Cron file not owned by root: {cf} (uid={uid})")
                if status == 'pass':
                    status = 'warn'

        except Exception as e:
            findings.append(f"ERROR: Could not stat {cf}: {e}")

    # Check user crontabs
    try:
        spool_dir = '/var/spool/cron/crontabs'
        if _is_dir(spool_dir):
            users_with_cron = _list_dir(spool_dir)
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
        if _is_dir(at_spool):
            at_jobs = [f for f in _list_dir(at_spool) if not f.startswith('.')]
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
        if not _is_file(cf):
            continue
        try:
            content = _read_file(cf)
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
