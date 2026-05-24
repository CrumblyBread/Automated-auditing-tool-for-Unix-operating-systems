#!/usr/bin/env python3
import subprocess
import os
import re
from datetime import datetime, timedelta


BACKUP_TOOLS = {
    "rsnapshot": (
        ["/var/log/rsnapshot.log", "/var/log/rsnapshot"],
        r"(completed successfully|rsnapshot.*\s+$)"
    ),
    "borgbackup": (
        ["/var/log/borg.log", "/var/log/borgbackup.log"],
        r"(Archive name:|terminating with success)"
    ),
    "borg": (
        ["/var/log/borg.log"],
        r"(Archive name:|terminating with success)"
    ),
    "restic": (
        ["/var/log/restic.log"],
        r"(snapshot .* saved|successfully saved)"
    ),
    "bacula-fd": (
        ["/var/log/bacula/bacula.log"],
        r"(Backup OK|JobStatus=T)"
    ),
    "amanda": (
        ["/var/log/amanda/"],
        r"(SUCCESS)"
    ),
    "timeshift": (
        ["/var/log/timeshift/"],
        r"(Backup saved successfully)"
    ),
    "duplicati": (
        ["/var/log/duplicati.log"],
        r"(backup completed)"
    ),
}

DATE_PATTERNS = [
    (r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2})", "%Y-%m-%dT%H:%M"),
    (r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2})", "%Y-%m-%d %H:%M"),
    (r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", "%b %d %H:%M:%S"),
]


def _cmd(args):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=10)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return -1, "", f"nenájdený: {args[0]}"
    except Exception as e:
        return -1, "", str(e)


def _is_installed(binary):
    rc, _, _ = _cmd(["which", binary])
    return rc == 0


def _read_log_tail(path, lines=200):
    try:
        if os.path.isdir(path):
            files = sorted(
                [os.path.join(path, f) for f in os.listdir(path)
                 if os.path.isfile(os.path.join(path, f))],
                key=os.path.getmtime, reverse=True
            )
            if not files:
                return ""
            path = files[0]
        with open(path, "r", errors="replace") as f:
            all_lines = f.readlines()
            return "".join(all_lines[-lines:])
    except (PermissionError, FileNotFoundError):
        return ""


def _extract_last_date(text):
    found_dates = []
    for pattern, fmt in DATE_PATTERNS:
        for match in re.finditer(pattern, text):
            raw = match.group(1).replace("T", " ")
            try:
                if fmt == "%b %d %H:%M:%S":
                    dt = datetime.strptime(f"{datetime.now().year} {raw}", f"%Y {fmt}")
                else:
                    dt = datetime.strptime(raw, "%Y-%m-%d %H:%M")
                found_dates.append(dt)
            except ValueError:
                continue
    return max(found_dates) if found_dates else None


def _check_cron_for_backup(tool_name):
    cron_paths = [
        "/etc/crontab",
        "/etc/cron.d/",
        "/etc/cron.daily/",
        "/etc/cron.weekly/",
        "/var/spool/cron/crontabs/",
    ]
    for path in cron_paths:
        try:
            if os.path.isdir(path):
                for fname in os.listdir(path):
                    fpath = os.path.join(path, fname)
                    try:
                        with open(fpath, "r", errors="replace") as f:
                            if tool_name in f.read():
                                return True
                    except (PermissionError, IsADirectoryError):
                        continue
            elif os.path.isfile(path):
                with open(path, "r", errors="replace") as f:
                    if tool_name in f.read():
                        return True
        except (PermissionError, FileNotFoundError):
            continue
    return False


def run(params=None):
    if params is None:
        params = {}

    max_age_days = params.get("max_backup_age_days", 7)
    require_cron = params.get("require_cron_entry", True)

    findings = []
    installed_tools = []
    tools_with_recent_backup = []
    tools_with_old_backup = []
    tools_without_logs = []

    now = datetime.now()
    age_threshold = now - timedelta(days=max_age_days)

    for tool, (log_paths, success_pattern) in BACKUP_TOOLS.items():
        if not _is_installed(tool):
            continue

        installed_tools.append(tool)
        findings.append(f"INFO: Zálohovací nástroj nájdený: {tool}")

        last_backup_date = None
        log_found = False

        for log_path in log_paths:
            log_text = _read_log_tail(log_path)
            if not log_text:
                continue
            log_found = True

            if re.search(success_pattern, log_text, re.IGNORECASE):
                date = _extract_last_date(log_text)
                if date:
                    if last_backup_date is None or date > last_backup_date:
                        last_backup_date = date

        if not log_found:
            tools_without_logs.append(tool)
            findings.append(
                f"WARNING: Nástroj '{tool}' nainštalovaný, ale log nenájdený alebo neprístupný"
            )
        elif last_backup_date is None:
            tools_without_logs.append(tool)
            findings.append(
                f"WARNING: Nástroj '{tool}' — v logu nebola nájdená úspešná záloha"
            )
        elif last_backup_date >= age_threshold:
            tools_with_recent_backup.append(tool)
            age = (now - last_backup_date).days
            findings.append(
                f"OK: '{tool}' — posledná záloha pred {age} dňom/dňami "
                f"({last_backup_date.strftime('%Y-%m-%d %H:%M')})"
            )
        else:
            tools_with_old_backup.append(tool)
            age = (now - last_backup_date).days
            findings.append(
                f"FAIL: '{tool}' — posledná záloha je stará {age} dní "
                f"(prah: {max_age_days} dní, dátum: {last_backup_date.strftime('%Y-%m-%d %H:%M')})"
            )

        if require_cron:
            if _check_cron_for_backup(tool):
                findings.append(f"OK: '{tool}' má cron záznam pre automatické zálohovanie")
            else:
                findings.append(
                    f"WARNING: '{tool}' — cron záznam pre automatické zálohovanie nebol nájdený"
                )

    if not installed_tools:
        status = "FAIL"
        message = "Žiadny zálohovací nástroj nebol nájdený — NIS2 vyžaduje kontinuitu prevádzky"
    elif tools_with_old_backup:
        status = "FAIL"
        message = (
            f"Zálohy sú zastarané: {', '.join(tools_with_old_backup)} "
            f"prekročili prah {max_age_days} dní"
        )
    elif tools_without_logs:
        status = "WARNING"
        message = (
            f"Zálohovací nástroj(e) nájdené, ale zálohu sa nepodarilo overiť: "
            f"{', '.join(tools_without_logs)}"
        )
    elif tools_with_recent_backup:
        status = "OK"
        message = (
            f"Zálohovanie je aktívne a aktuálne: {', '.join(tools_with_recent_backup)}"
        )
    else:
        status = "WARNING"
        message = "Zálohovací nástroj nájdený, ale stav zálohovania nie je možné overiť"

    return {
        "test_name": "Backup Verification Check",
        "status": status,
        "message": message,
        "max_backup_age_days": max_age_days,
        "installed_tools": installed_tools,
        "tools_with_recent_backup": tools_with_recent_backup,
        "tools_with_old_backup": tools_with_old_backup,
        "tools_without_verifiable_logs": tools_without_logs,
        "findings": findings,
        "recommendation": (
            "Nainštalujte a nakonfigurujte zálohovací nástroj (napr. borgbackup alebo restic). "
            "Nastavte automatické zálohovanie cez cron alebo systemd timer. "
            f"Uistite sa že zálohy prebehli v posledných {max_age_days} dňoch. "
            "NIS2 vyžaduje preukázateľnú schopnosť obnovy po incidente."
        ) if status != "OK" else "Zálohovanie je v poriadku, udržujte pravidelný cyklus",
    }


if __name__ == "__main__":
    import json
    result = run({"max_backup_age_days": 7, "require_cron_entry": True})
    print(json.dumps(result, indent=2, ensure_ascii=False))
