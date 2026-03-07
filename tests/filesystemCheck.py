#!/usr/bin/env python3
import subprocess
import os

def run(params=None):
    if params is None:
        params = {}

    require_noexec_tmp = params.get('require_noexec_tmp', True)
    require_nosuid_removable = params.get('require_nosuid_removable', True)
    check_world_writable_mounts = params.get('check_world_writable_mounts', True)
    findings = []
    status = 'pass'

    # Parse /proc/mounts
    mounts = []
    try:
        with open('/proc/mounts') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4:
                    device, mountpoint, fstype, options_str = parts[0], parts[1], parts[2], parts[3]
                    options = options_str.split(',')
                    mounts.append({'device': device, 'mountpoint': mountpoint, 'fstype': fstype, 'options': options})
    except Exception as e:
        findings.append(f"ERROR: Could not read /proc/mounts: {e}")
        return {'test_name': 'Filesystem Security Check', 'status': 'error', 'findings': findings}

    print(f"[*] Checking {len(mounts)} mount(s)")

    # Check /tmp
    tmp_mount = next((m for m in mounts if m['mountpoint'] == '/tmp'), None)
    if tmp_mount:
        opts = tmp_mount['options']
        if 'noexec' in opts:
            findings.append("PASS: /tmp mounted with noexec")
        else:
            findings.append("WARN: /tmp is NOT mounted with noexec")
            if require_noexec_tmp and status == 'pass':
                status = 'warn'
        if 'nosuid' in opts:
            findings.append("PASS: /tmp mounted with nosuid")
        else:
            findings.append("WARN: /tmp is NOT mounted with nosuid")
        if 'nodev' in opts:
            findings.append("PASS: /tmp mounted with nodev")
        else:
            findings.append("WARN: /tmp is NOT mounted with nodev")
    else:
        findings.append("INFO: /tmp is not a separate mount point")

    # Check /var/tmp
    var_tmp = next((m for m in mounts if m['mountpoint'] == '/var/tmp'), None)
    if var_tmp:
        if 'noexec' not in var_tmp['options']:
            findings.append("WARN: /var/tmp not mounted with noexec")
            if status == 'pass':
                status = 'warn'

    # Check removable/external media mounts
    removable_types = ['vfat', 'ntfs', 'exfat', 'iso9660', 'udf']
    for m in mounts:
        if m['fstype'] in removable_types:
            if require_nosuid_removable and 'nosuid' not in m['options']:
                findings.append(f"WARN: {m['mountpoint']} ({m['fstype']}) not mounted with nosuid")
                if status == 'pass':
                    status = 'warn'
            if 'noexec' not in m['options']:
                findings.append(f"WARN: {m['mountpoint']} ({m['fstype']}) not mounted with noexec")

    # Check /home — should not have exec issues typically, but flag if nosuid missing
    home_mount = next((m for m in mounts if m['mountpoint'] == '/home'), None)
    if home_mount:
        if 'nosuid' not in home_mount['options']:
            findings.append("WARN: /home not mounted with nosuid")
            if status == 'pass':
                status = 'warn'
        if 'nodev' not in home_mount['options']:
            findings.append("WARN: /home not mounted with nodev")

    # Check for world-writable mount points (excluding tmpfs like /run)
    if check_world_writable_mounts:
        skip_fs = {'tmpfs', 'devtmpfs', 'sysfs', 'proc', 'devpts', 'cgroup', 'cgroup2', 'securityfs', 'pstore', 'efivarfs'}
        for m in mounts:
            if m['fstype'] in skip_fs:
                continue
            mp = m['mountpoint']
            try:
                st = os.stat(mp)
                import stat as statmod
                if st.st_mode & statmod.S_IWOTH:
                    findings.append(f"WARN: Mount point {mp} is world-writable")
                    if status == 'pass':
                        status = 'warn'
            except Exception:
                pass

    if status == 'pass':
        findings.append("PASS: No critical filesystem security issues found")

    return {'test_name': 'Filesystem Security Check', 'status': status, 'findings': findings}


if __name__ == "__main__":
    print(run())
