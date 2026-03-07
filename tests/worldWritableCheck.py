#!/usr/bin/env python3
import subprocess
import os

def run(params=None):
    if params is None:
        params = {}

    scan_paths = params.get('scan_paths', ['/etc', '/usr', '/bin', '/sbin'])
    exclude_paths = params.get('exclude_paths', ['/proc', '/sys', '/dev'])
    max_findings = params.get('max_findings', 50)
    findings = []
    status = 'pass'
    ww_files = []

    print(f"[*] Scanning for world-writable files in: {scan_paths}")

    try:
        # Build exclusion args
        exclude_args = []
        for ep in exclude_paths:
            exclude_args += ['-path', ep, '-prune', '-o']

        for scan_path in scan_paths:
            if not os.path.isdir(scan_path):
                continue
            cmd = ['find', scan_path] + exclude_args + ['-perm', '-0002', '-not', '-type', 'l', '-print']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            for line in result.stdout.splitlines():
                f = line.strip()
                if f and f not in exclude_paths:
                    ww_files.append(f)

    except subprocess.TimeoutExpired:
        findings.append("ERROR: Find timed out")
        return {'test_name': 'World-Writable Files Check', 'status': 'error', 'findings': findings}

    print(f"[*] Found {len(ww_files)} world-writable file(s)")

    if ww_files:
        findings.append(f"WARN: {len(ww_files)} world-writable file(s) found")
        status = 'warn'

        # Check if any are in critical paths
        critical_paths = ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin']
        for f in ww_files[:max_findings]:
            is_critical = any(f.startswith(cp) for cp in critical_paths)
            severity = "FAIL" if is_critical else "WARN"
            findings.append(f"{severity}: World-writable: {f}")
            if is_critical:
                status = 'fail'

        if len(ww_files) > max_findings:
            findings.append(f"INFO: ... and {len(ww_files) - max_findings} more (truncated)")
    else:
        findings.append("PASS: No world-writable files found in scanned paths")

    return {'test_name': 'World-Writable Files Check', 'status': status, 'count': len(ww_files), 'findings': findings}


if __name__ == "__main__":
    print(run())
