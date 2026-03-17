#!/usr/bin/env bash
# ============================================================
# cronAuditCheck.sh — Cron Jobs Audit
# Params (env vars):
#   CHECK_WORLD_WRITABLE  (default: true)
#   CHECK_UNOWNED         (default: true)
# ============================================================

CHECK_WORLD_WRITABLE="${CHECK_WORLD_WRITABLE:-true}"
CHECK_UNOWNED="${CHECK_UNOWNED:-true}"

STATUS="pass"
FINDINGS=()

CRON_FILES=("/etc/crontab" "/etc/anacrontab")
CRON_DIRS=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")

# Collect all cron files
for d in "${CRON_DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    while IFS= read -r f; do
        CRON_FILES+=("$f")
    done < <(find "$d" -maxdepth 1 -type f 2>/dev/null)
done

echo "[*] Scanning ${#CRON_FILES[@]} cron file(s)"

for cf in "${CRON_FILES[@]}"; do
    [[ -f "$cf" ]] || continue

    PERMS=$(stat -c "%a" "$cf" 2>/dev/null) || continue
    OWNER_UID=$(stat -c "%u" "$cf" 2>/dev/null)

    # World-writable: last octet has write bit
    OTHERS=$(( 8#$PERMS % 8 ))
    if [[ "$CHECK_WORLD_WRITABLE" == "true" ]] && (( (OTHERS & 2) != 0 )); then
        FINDINGS+=("FAIL: Cron file is world-writable: ${cf} (${PERMS})")
        STATUS="fail"
    else
        FINDINGS+=("PASS: ${cf} (${PERMS})")
    fi

    # Owned by root?
    if [[ "$CHECK_UNOWNED" == "true" && "$OWNER_UID" != "0" ]]; then
        FINDINGS+=("WARN: Cron file not owned by root: ${cf} (uid=${OWNER_UID})")
        [[ "$STATUS" == "pass" ]] && STATUS="warn"
    fi
done

# User crontab spool
SPOOL="/var/spool/cron/crontabs"
if [[ -d "$SPOOL" ]]; then
    USERS=$(ls "$SPOOL" 2>/dev/null)
    if [[ -n "$USERS" ]]; then
        FINDINGS+=("INFO: Users with crontabs: $(echo $USERS | tr '\n' ' ')")
    else
        FINDINGS+=("INFO: No user crontabs found")
    fi
else
    FINDINGS+=("INFO: No crontab spool directory found")
fi

# at jobs
AT_SPOOL="/var/spool/at"
if [[ -d "$AT_SPOOL" ]]; then
    AT_COUNT=$(find "$AT_SPOOL" -maxdepth 1 -type f ! -name '.*' 2>/dev/null | wc -l)
    if (( AT_COUNT > 0 )); then
        FINDINGS+=("INFO: ${AT_COUNT} pending at job(s) found")
    else
        FINDINGS+=("INFO: No pending at jobs")
    fi
fi

# Scan content for suspicious patterns
SUSPICIOUS_PATTERNS=("wget" "curl" "bash -i" "nc " "ncat" "python -c" "perl -e" "/dev/tcp" "base64 -d" "eval")

for cf in "${CRON_FILES[@]}"; do
    [[ -f "$cf" && -r "$cf" ]] || continue
    for pat in "${SUSPICIOUS_PATTERNS[@]}"; do
        if grep -qF -- "$pat" "$cf" 2>/dev/null; then
            FINDINGS+=("WARN: Suspicious pattern '${pat}' found in ${cf}")
            [[ "$STATUS" == "pass" ]] && STATUS="warn"
        fi
    done
done

[[ ${#FINDINGS[@]} -eq 0 ]] && FINDINGS+=("INFO: No cron files found to audit")

echo ""
echo "=== Cron Jobs Audit ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
