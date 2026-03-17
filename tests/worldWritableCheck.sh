#!/usr/bin/env bash
# ============================================================
# worldWritableCheck.sh — World-Writable Files Check
# Params (env vars):
#   SCAN_PATHS      (default: "/etc /usr /bin /sbin" — space-separated)
#   EXCLUDE_PATHS   (default: "/proc /sys /dev" — space-separated)
#   MAX_FINDINGS    (default: 50)
# ============================================================

SCAN_PATHS="${SCAN_PATHS:-/etc /usr /bin /sbin}"
EXCLUDE_PATHS="${EXCLUDE_PATHS:-/proc /sys /dev}"
MAX_FINDINGS="${MAX_FINDINGS:-50}"

STATUS="pass"
FINDINGS=()
WW_FILES=()

CRITICAL_PATHS="/etc /bin /sbin /usr/bin /usr/sbin"

# Build find exclusion args
FIND_EXCL=()
for ep in $EXCLUDE_PATHS; do
    FIND_EXCL+=(-path "$ep" -prune -o)
done

echo "[*] Scanning for world-writable files in: ${SCAN_PATHS}"

for scan_path in $SCAN_PATHS; do
    [[ -d "$scan_path" ]] || continue
    while IFS= read -r filepath; do
        [[ -z "$filepath" ]] && continue
        WW_FILES+=("$filepath")
    done < <(find "$scan_path" "${FIND_EXCL[@]}" -perm -0002 ! -type l -print 2>/dev/null)
done

echo "[*] Found ${#WW_FILES[@]} world-writable file(s)"

if (( ${#WW_FILES[@]} > 0 )); then
    FINDINGS+=("WARN: ${#WW_FILES[@]} world-writable file(s) found")
    [[ "$STATUS" == "pass" ]] && STATUS="warn"

    COUNT=0
    for f in "${WW_FILES[@]}"; do
        (( COUNT >= MAX_FINDINGS )) && break
        # Check if in a critical path
        IS_CRITICAL=false
        for cp in $CRITICAL_PATHS; do
            if [[ "$f" == "${cp}/"* || "$f" == "$cp" ]]; then
                IS_CRITICAL=true
                break
            fi
        done

        if [[ "$IS_CRITICAL" == "true" ]]; then
            FINDINGS+=("FAIL: World-writable in critical path: ${f}")
            STATUS="fail"
        else
            FINDINGS+=("WARN: World-writable: ${f}")
        fi
        (( COUNT++ ))
    done

    REMAINING=$(( ${#WW_FILES[@]} - MAX_FINDINGS ))
    (( REMAINING > 0 )) && FINDINGS+=("INFO: ... and ${REMAINING} more (truncated at ${MAX_FINDINGS})")
else
    FINDINGS+=("PASS: No world-writable files found in scanned paths")
fi

echo ""
echo "=== World-Writable Files Check ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
