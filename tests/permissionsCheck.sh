#!/usr/bin/env bash
# ============================================================
# permissionsCheck.sh — Home Directory Permissions Check
# Params (env vars):
#   HOME_DIRECTORY         (default: /home)
#   CHECK_WORLD_READABLE   (default: true)
#   CHECK_WORLD_WRITABLE   (default: true)
#   CHECK_GROUP_WRITABLE   (default: true)
#   MAX_PERMISSIONS        (default: 755)
# ============================================================

HOME_DIRECTORY="${HOME_DIRECTORY:-/home}"
CHECK_WORLD_READABLE="${CHECK_WORLD_READABLE:-true}"
CHECK_WORLD_WRITABLE="${CHECK_WORLD_WRITABLE:-true}"
CHECK_GROUP_WRITABLE="${CHECK_GROUP_WRITABLE:-true}"
MAX_PERMISSIONS="${MAX_PERMISSIONS:-755}"

STATUS="pass"
FINDINGS=()

if [[ ! -d "$HOME_DIRECTORY" ]]; then
    echo "ERROR: Home directory ${HOME_DIRECTORY} not found"
    exit 1
fi

echo "[*] Scanning ${HOME_DIRECTORY} ..."

for user_dir in "$HOME_DIRECTORY"/*/; do
    [[ -d "$user_dir" ]] || continue
    PERMS=$(stat -c "%a" "$user_dir" 2>/dev/null) || continue
    echo "[*] ${user_dir}: ${PERMS}"

    # Compare numerically
    if (( 8#$PERMS > 8#$MAX_PERMISSIONS )); then
        FINDINGS+=("WARN: ${user_dir} has permissions ${PERMS} (max allowed: ${MAX_PERMISSIONS})")
        [[ "$STATUS" == "pass" ]] && STATUS="warn"
    fi

    # World-writable: last octet has write bit (others write = bit 1 of last digit)
    OTHERS=$(( 8#$PERMS % 8 ))
    if [[ "$CHECK_WORLD_WRITABLE" == "true" ]] && (( (OTHERS & 2) != 0 )); then
        FINDINGS+=("FAIL: ${user_dir} is WORLD-WRITABLE (${PERMS})")
        STATUS="fail"
    fi

    # World-readable: others read bit
    if [[ "$CHECK_WORLD_READABLE" == "true" ]] && (( (OTHERS & 4) != 0 )); then
        FINDINGS+=("WARN: ${user_dir} is world-readable (${PERMS})")
        [[ "$STATUS" == "pass" ]] && STATUS="warn"
    fi

    # Group-writable: group digit bit 1
    GROUP=$(( (8#$PERMS / 8) % 8 ))
    if [[ "$CHECK_GROUP_WRITABLE" == "true" ]] && (( (GROUP & 2) != 0 )); then
        FINDINGS+=("WARN: ${user_dir} is group-writable (${PERMS})")
        [[ "$STATUS" == "pass" ]] && STATUS="warn"
    fi

    # .ssh directory
    SSH_DIR="${user_dir}.ssh"
    if [[ -d "$SSH_DIR" ]]; then
        SSH_PERMS=$(stat -c "%a" "$SSH_DIR" 2>/dev/null)
        if [[ "$SSH_PERMS" == "700" ]]; then
            FINDINGS+=("PASS: ${SSH_DIR} has correct permissions (700)")
        else
            FINDINGS+=("FAIL: ${SSH_DIR} has permissions ${SSH_PERMS} (expected 700)")
            STATUS="fail"
        fi

        AUTH_KEYS="${SSH_DIR}/authorized_keys"
        if [[ -f "$AUTH_KEYS" ]]; then
            AK_PERMS=$(stat -c "%a" "$AUTH_KEYS" 2>/dev/null)
            if [[ "$AK_PERMS" == "600" || "$AK_PERMS" == "644" ]]; then
                FINDINGS+=("PASS: ${AUTH_KEYS} permissions OK (${AK_PERMS})")
            else
                FINDINGS+=("WARN: ${AUTH_KEYS} has unusual permissions ${AK_PERMS}")
                [[ "$STATUS" == "pass" ]] && STATUS="warn"
            fi
        fi
    fi
done

[[ ${#FINDINGS[@]} -eq 0 ]] && FINDINGS+=("PASS: All home directories have acceptable permissions")

echo ""
echo "=== Home Directory Permissions Check ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
