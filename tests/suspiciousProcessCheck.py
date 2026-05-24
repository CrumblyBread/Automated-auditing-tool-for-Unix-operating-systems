#!/usr/bin/env python3
import subprocess
import os


SUSPICIOUS_DIRS = ["/tmp", "/dev/shm", "/var/tmp", "/run/shm", "/run/user"]


def _get_proc_pids():
    pids = set()
    try:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                pids.add(int(entry))
    except PermissionError:
        pass
    return pids


def _get_ps_pids():
    pids = set()
    try:
        result = subprocess.run(
            ["ps", "-e", "-o", "pid="],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.isdigit():
                pids.add(int(line))
    except Exception:
        pass
    return pids


def _check_deleted_exe(pid):
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
        return "(deleted)" in exe
    except (PermissionError, FileNotFoundError, OSError):
        return False


def _get_exe_path(pid):
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except (PermissionError, FileNotFoundError, OSError):
        return None


def _get_process_name(pid):
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except (PermissionError, FileNotFoundError, OSError):
        return f"PID_{pid}"


def run(params=None):
    if params is None:
        params = {}

    extra_suspicious_dirs = params.get("extra_suspicious_dirs", [])
    suspicious_dirs = SUSPICIOUS_DIRS + extra_suspicious_dirs

    findings = []
    deleted_procs = []
    suspicious_path_procs = []
    hidden_pids = []

    proc_pids = _get_proc_pids()
    ps_pids = _get_ps_pids()

    if proc_pids and ps_pids:
        diff = proc_pids - ps_pids - {1}
        for pid in diff:
            if os.path.exists(f"/proc/{pid}"):
                name = _get_process_name(pid)
                hidden_pids.append({"pid": pid, "name": name})
                findings.append(
                    f"CRITICAL: PID {pid} ({name}) viditeľný v /proc ale nie v ps — možný rootkit"
                )
    else:
        findings.append("WARNING: Nepodarilo sa porovnať /proc a ps — kontrola skrytých PID preskočená")

    for pid in list(proc_pids):
        if _check_deleted_exe(pid):
            name = _get_process_name(pid)
            deleted_procs.append({"pid": pid, "name": name})
            findings.append(
                f"CRITICAL: Proces {name} (PID {pid}) beží zo zmazanej binárky — možná injektáž"
            )

    for pid in list(proc_pids):
        exe = _get_exe_path(pid)
        if exe is None:
            continue
        exe_clean = exe.replace(" (deleted)", "")
        for sdir in suspicious_dirs:
            if exe_clean.startswith(sdir):
                name = _get_process_name(pid)
                suspicious_path_procs.append({"pid": pid, "name": name, "exe": exe_clean})
                findings.append(
                    f"WARNING: Proces {name} (PID {pid}) spustený z podozrivého adresára: {exe_clean}"
                )
                break

    if not findings:
        status = "OK"
        message = "Žiadne podozrivé procesy nenájdené"
    elif deleted_procs or hidden_pids:
        status = "CRITICAL"
        message = (
            f"Nájdené kritické anomálie: "
            f"{len(deleted_procs)} zmazaných bináriek, "
            f"{len(hidden_pids)} skrytých PID"
        )
    elif suspicious_path_procs:
        status = "WARNING"
        message = f"Nájdených {len(suspicious_path_procs)} procesov spustených z podozrivých adresárov"
    else:
        status = "WARNING"
        message = "Nájdené drobné anomálie pri kontrole procesov"

    return {
        "test_name": "Suspicious Process Check",
        "status": status,
        "message": message,
        "hidden_pids": hidden_pids,
        "deleted_exe_processes": deleted_procs,
        "suspicious_path_processes": suspicious_path_procs,
        "findings": findings,
        "recommendation": (
            "Preskúmajte uvedené procesy manuálne. "
            "Skryté PID alebo zmazané binárky môžu indikovať rootkit alebo aktívny útok. "
            "Zvážte spustenie nástroja rkhunter alebo chkrootkit pre hlbšiu analýzu."
        ) if findings else "Žiadna akcia nie je potrebná",
    }


if __name__ == "__main__":
    import json
    result = run({"extra_suspicious_dirs": []})
    print(json.dumps(result, indent=2, ensure_ascii=False))
