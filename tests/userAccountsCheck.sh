#!/usr/bin/env bash
# ============================================================
# userAccountsCheck.sh — User Accounts Audit
# Params (env vars):
#   CHECK_UID0          (default: true)
#   CHECK_NO_PASSWORD   (default: true)
#   CHECK_LOGIN_SHELL   (default: true)
#   ALLOWED_UID0_USERS  (default: "root" — space-separated)
#   CHECK_SUDOERS       (default: true)
# ============================================================

CHECK_UID0="${CHECK_UID0:-true}"
CHECK_NO_PASSWORD="${CHECK_NO_PASSWORD:-true}"
CHECK_LOGIN_SHELL="${CHECK_LOGIN_SHELL:-true}"
ALLOWED_UID0_USERS="${ALLOWED_UID0_USERS:-root}"
CHECK_SUDOERS="${CHECK_SUDOERS:-true}"

STATUS="pass"
FINDINGS=()

declare -A ALLOWED_UID0
for u in $ALLOWED_UID0_USERS; do ALLOWED_UID0[$u]=1; done

NON_LOGIN_SHELLS="/usr/sbin/nologin /bin/false /sbin/nologin /bin/nologin"

# ---------- UID 0 accounts ----------
if [[ "$CHECK_UID0" == "true" ]]; then
    while IFS=: read -r username _ uid _; do
        if [[ "$uid" == "0" ]]; then
            if [[ "${ALLOWED_UID0[$username]+_}" ]]; then
                FINDINGS+=("PASS: Expected UID 0 account: ${username}")
            else
                FINDINGS+=("CRITICAL: Unexpected UID 0 account: ${username}")
                STATUS="critical"
            fi
        fi
    done < /etc/passwd
fi

# ---------- Empty passwords ----------
if [[ "$CHECK_NO_PASSWORD" == "true" ]]; then
    if [[ -r /etc/shadow ]]; then
        while IFS=: read -r username password _; do
            if [[ -z "$password" ]]; then
                FINDINGS+=("CRITICAL: User '${username}' has no password set")
                STATUS="critical"
            elif [[ "$password" == "!" || "$password" == "!!" || "$password" == "*" ]]; then
                FINDINGS+=("INFO: User '${username}' account is locked")
            fi
        done < /etc/shadow
        FINDINGS+=("PASS: No accounts with empty passwords detected")
    else
        FINDINGS+=("INFO: Cannot read /etc/shadow (run as root)")
    fi
fi

# ---------- Service account login shells ----------
if [[ "$CHECK_LOGIN_SHELL" == "true" ]]; then
    while IFS=: read -r username _ uid _ _ _ shell; do
        if (( uid > 0 && uid < 1000 )); then
            IS_NOLOGIN=false
            for nls in $NON_LOGIN_SHELLS; do
                [[ "$shell" == "$nls" ]] && IS_NOLOGIN=true && break
            done
            if [[ "$IS_NOLOGIN" == "false" ]]; then
                FINDINGS+=("WARN: Service account with login shell: ${username} (uid=${uid}, shell=${shell})")
                [[ "$STATUS" == "pass" ]] && STATUS="warn"
            fi
        fi
    done < /etc/passwd
    # Check if any warnings were added; if not, note pass
fi

# ---------- Duplicate UIDs ----------
declare -A UID_MAP
while IFS=: read -r username _ uid _; do
    if [[ "${UID_MAP[$uid]+_}" ]]; then
        # Skip uid 65534 (nobody)
        (( uid != 65534 )) && FINDINGS+=("WARN: Duplicate UID ${uid} — shared by: ${UID_MAP[$uid]} and ${username}")
        [[ "$STATUS" == "pass" ]] && STATUS="warn"
    else
        UID_MAP[$uid]="$username"
    fi
done < /etc/passwd

# ---------- Sudoers check ----------
if [[ "$CHECK_SUDOERS" == "true" ]]; then
    # Members of sudo group
    SUDO_MEMBERS=$(getent group sudo 2>/dev/null | cut -d: -f4)
    WHEEL_MEMBERS=$(getent group wheel 2>/dev/null | cut -d: -f4)
    [[ -n "$SUDO_MEMBERS" ]] && FINDINGS+=("INFO: sudo group members: ${SUDO_MEMBERS}")
    [[ -n "$WHEEL_MEMBERS" ]] && FINDINGS+=("INFO: wheel group members: ${WHEEL_MEMBERS}")

    # Check for NOPASSWD entries
    SUDOERS_FILES=("/etc/sudoers")
    [[ -d /etc/sudoers.d ]] && while IFS= read -r f; do SUDOERS_FILES+=("$f"); done < <(find /etc/sudoers.d -type f 2>/dev/null)

    for sf in "${SUDOERS_FILES[@]}"; do
        [[ -r "$sf" ]] || { FINDINGS+=("INFO: Cannot read ${sf} (need root)"); continue; }
        while IFS= read -r line; do
            # Skip comments and blank lines
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue
            if [[ "$line" == *NOPASSWD* ]]; then
                FINDINGS+=("WARN: NOPASSWD entry in ${sf}: ${line}")
                [[ "$STATUS" == "pass" ]] && STATUS="warn"
            fi
        done < "$sf"
    done
fi

echo ""
echo "=== User Accounts Audit ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
