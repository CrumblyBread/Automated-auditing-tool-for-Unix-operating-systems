#!/usr/bin/env python3
import subprocess
import os

def run(params=None):
    if params is None:
        params = {}

    require_root_encrypted = params.get('require_root_encrypted', False)
    check_swap = params.get('check_swap_encrypted', True)
    findings = []
    status = 'pass'

    # Check for LUKS devices via lsblk
    luks_devices = []
    try:
        result = subprocess.run(
            ['lsblk', '-o', 'NAME,TYPE,FSTYPE,MOUNTPOINT', '--json'],
            capture_output=True, text=True
        )
        import json
        data = json.loads(result.stdout)
        def walk(devices):
            for d in devices:
                if d.get('type') == 'crypt' or d.get('fstype') == 'crypto_LUKS':
                    luks_devices.append(d.get('name', 'unknown'))
                if d.get('children'):
                    walk(d['children'])
        walk(data.get('blockdevices', []))

        if luks_devices:
            findings.append(f"PASS: LUKS encrypted device(s) detected: {', '.join(luks_devices)}")
        else:
            findings.append("INFO: No LUKS encrypted devices detected via lsblk")

    except (FileNotFoundError, Exception):
        # Fallback: check /proc/crypto and dm-crypt
        try:
            result = subprocess.run(['dmsetup', 'ls', '--target', 'crypt'], capture_output=True, text=True)
            lines = [l for l in result.stdout.splitlines() if l.strip() and 'No devices' not in l]
            if lines:
                findings.append(f"PASS: dm-crypt device(s) found: {len(lines)} device(s)")
                for l in lines:
                    luks_devices.append(l.split()[0])
            else:
                findings.append("INFO: No dm-crypt devices found")
        except FileNotFoundError:
            findings.append("INFO: dmsetup not available — cannot check disk encryption")

    # Check if root is on encrypted volume
    try:
        result = subprocess.run(['df', '/'], capture_output=True, text=True)
        root_device = result.stdout.splitlines()[-1].split()[0]
        findings.append(f"INFO: Root filesystem device: {root_device}")
        if any(ldev in root_device for ldev in luks_devices) or 'dm-' in root_device:
            findings.append("PASS: Root filesystem appears to be on an encrypted volume")
        else:
            msg = "INFO: Root filesystem does not appear to be encrypted"
            findings.append(("WARN: " if require_root_encrypted else "INFO: ") + msg.replace("INFO: ", ""))
            if require_root_encrypted:
                status = 'warn'
    except Exception as e:
        findings.append(f"ERROR: Could not determine root device: {e}")

    # Check swap encryption
    if check_swap:
        try:
            with open('/proc/swaps') as f:
                swap_lines = [l for l in f.readlines()[1:] if l.strip()]
            if swap_lines:
                for sl in swap_lines:
                    swap_dev = sl.split()[0]
                    findings.append(f"INFO: Swap device: {swap_dev}")
                    if any(ldev in swap_dev for ldev in luks_devices) or 'dm-' in swap_dev or 'zram' in swap_dev:
                        findings.append(f"PASS: Swap ({swap_dev}) appears to be encrypted or compressed")
                    else:
                        findings.append(f"WARN: Swap ({swap_dev}) may not be encrypted")
                        if status == 'pass':
                            status = 'warn'
            else:
                findings.append("INFO: No swap configured")
        except Exception as e:
            findings.append(f"INFO: Could not check swap: {e}")

    # Check for ecryptfs home directories
    try:
        result = subprocess.run(['mount'], capture_output=True, text=True)
        ecrypt = [l for l in result.stdout.splitlines() if 'ecryptfs' in l]
        if ecrypt:
            findings.append(f"INFO: ecryptfs home directory encryption detected ({len(ecrypt)} mount(s))")
        else:
            findings.append("INFO: No ecryptfs home directory encryption detected")
    except Exception:
        pass

    return {'test_name': 'Disk Encryption Check', 'status': status, 'findings': findings}


if __name__ == "__main__":
    print(run())
