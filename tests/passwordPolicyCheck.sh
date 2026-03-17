#!/usr/bin/env bash
# ============================================================
# passwordPolicyCheck.sh — Password Policy Check
# Params (env vars):
#   MIN_PASSWORD_LENGTH    (default: 12)
#   CHECK_COMPLEXITY       (default: true)
#   CHECK_EXPIRY           (default: true)
#   MAX_PASSWORD_AGE_DAYS  (default: 90)
# ============================================================

MIN_PASSWORD_LENGTH="${MIN_PASSWORD_LENGTH:-12}"
CHECK_COMPLEXITY="${CHECK_COMPLEXITY:-true}"
CHECK_EXPIRY="${CHECK_EXPIRY:-true}"
MAX_PASSWORD_AGE_DAYS="${MAX_PASSWORD_AGE_DAYS:-90}"

STATUS="pass"
FINDINGS=()

# ---------- /etc/login.defs ----------
LOGIN_DEFS="/etc/login.defs"
if [[ -f "$LOGIN_DEFS" ]]; then

    PASS_MIN_LEN=$(grep -P '^\s*PASS_MIN_LEN\s+\d+' "$LOGIN_DEFS" | awk '{print $2}')
    if [[ -n "$PASS_MIN_LEN" ]]; then
        if (( PASS_MIN_LEN >= MIN_PASSWORD_LENGTH )); then
            FINDINGS+=("PASS: PASS_MIN_LEN = ${PASS_MIN_LEN} (required: ${MIN_PASSWORD_LENGTH})")
        else
            FINDINGS+=("FAIL: PASS_MIN_LEN = ${PASS_MIN_LEN} (required: ${MIN_PASSWORD_LENGTH})")
            STATUS="fail"
        fi
    else
        FINDINGS+=("WARN: PASS_MIN_LEN not set in ${LOGIN_DEFS}")
        [[ "$STATUS" == "pass" ]] && STATUS="warn"
    fi

    if [[ "$CHECK_EXPIRY" == "true" ]]; then
        PASS_MAX_DAYS=$(grep -P '^\s*PASS_MAX_DAYS\s+\d+' "$LOGIN_DEFS" | awk '{print $2}')
        if [[ -n "$PASS_MAX_DAYS" ]]; then
            if (( PASS_MAX_DAYS <= MAX_PASSWORD_AGE_DAYS )); then
                FINDINGS+=("PASS: PASS_MAX_DAYS = ${PASS_MAX_DAYS} (max allowed: ${MAX_PASSWORD_AGE_DAYS})")
            else
                FINDINGS+=("FAIL: PASS_MAX_DAYS = ${PASS_MAX_DAYS} (max allowed: ${MAX_PASSWORD_AGE_DAYS})")
                STATUS="fail"
            fi
        else
            FINDINGS+=("WARN: PASS_MAX_DAYS not set in ${LOGIN_DEFS}")
            [[ "$STATUS" == "pass" ]] && STATUS="warn"
        fi

        PASS_MIN_DAYS=$(grep -P '^\s*PASS_MIN_DAYS\s+\d+' "$LOGIN_DEFS" | awk '{print $2}')
        [[ -n "$PASS_MIN_DAYS" ]] && FINDINGS+=("INFO: PASS_MIN_DAYS = ${PASS_MIN_DAYS}")
    fi
else
    FINDINGS+=("WARN: ${LOGIN_DEFS} not found")
    [[ "$STATUS" == "pass" ]] && STATUS="warn"
fi

# ---------- PAM pwquality / cracklib ----------
if [[ "$CHECK_COMPLEXITY" == "true" ]]; then
    PWQUALITY_CONF="/etc/security/pwquality.conf"
    if [[ -f "$PWQUALITY_CONF" ]]; then
        FINDINGS+=("INFO: pwquality.conf found")
        MINLEN=$(grep -P '^\s*minlen\s*=\s*\d+' "$PWQUALITY_CONF" | grep -oP '\d+' | head -1)
        if [[ -n "$MINLEN" ]]; then
            if (( MINLEN >= MIN_PASSWORD_LENGTH )); then
                FINDINGS+=("PASS: pwquality minlen = ${MINLEN}")
            else
                FINDINGS+=("FAIL: pwquality minlen = ${MINLEN} (required: ${MIN_PASSWORD_LENGTH})")
                STATUS="fail"
            fi
        fi
    else
        FINDINGS+=("WARN: /etc/security/pwquality.conf not found — password complexity may not be enforced")
        [[ "$STATUS" == "pass" ]] && STATUS="warn"
    fi

    # Check PAM common-password
    PAM_CP="/etc/pam.d/common-password"
    if [[ -f "$PAM_CP" ]]; then
        if grep -qE 'pwquality|cracklib' "$PAM_CP"; then
            FINDINGS+=("PASS: PAM password complexity module active in common-password")
        else
            FINDINGS+=("WARN: No complexity module (pwquality/cracklib) found in PAM common-password")
            [[ "$STATUS" == "pass" ]] && STATUS="warn"
        fi
    fi
fi

# ---------- empty passwords in /etc/shadow ----------
if [[ -r /etc/shadow ]]; then
    EMPTY_PASS=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
    if [[ -n "$EMPTY_PASS" ]]; then
        FINDINGS+=("CRITICAL: Users with empty passwords: ${EMPTY_PASS}")
        STATUS="critical"
    else
        FINDINGS+=("PASS: No accounts with empty passwords found")
    fi
else
    FINDINGS+=("INFO: Cannot read /etc/shadow (run as root)")
fi

echo ""
echo "=== Password Policy Check ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
