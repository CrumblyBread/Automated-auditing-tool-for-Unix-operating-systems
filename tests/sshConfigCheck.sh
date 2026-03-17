#!/usr/bin/env bash
# ============================================================
# sshConfigCheck.sh — SSH Configuration Check
# Params (env vars):
#   SSHD_CONFIG          (default: /etc/ssh/sshd_config)
#   ALLOW_ROOT_LOGIN     (default: false)
#   ALLOW_PASSWORD_AUTH  (default: false)
#   REQUIRE_PROTOCOL2    (default: true)
#   MAX_AUTH_TRIES       (default: 4)
# ============================================================

SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
ALLOW_ROOT_LOGIN="${ALLOW_ROOT_LOGIN:-false}"
ALLOW_PASSWORD_AUTH="${ALLOW_PASSWORD_AUTH:-false}"
REQUIRE_PROTOCOL2="${REQUIRE_PROTOCOL2:-true}"
MAX_AUTH_TRIES="${MAX_AUTH_TRIES:-4}"

STATUS="pass"
FINDINGS=()

if [[ ! -f "$SSHD_CONFIG" ]]; then
    FINDINGS+=("WARN: sshd_config not found at ${SSHD_CONFIG}")
    echo "=== SSH Configuration Check ==="
    echo "Status: warn"
    echo "  ${FINDINGS[0]}"
    exit 0
fi

# Helper: get effective (non-commented) value for a key
get_setting() {
    grep -iP "^\s*${1}\s+" "$SSHD_CONFIG" 2>/dev/null | tail -1 | awk '{print $2}'
}

# ---------- PermitRootLogin ----------
VAL=$(get_setting PermitRootLogin)
if [[ -n "$VAL" ]]; then
    case "${VAL,,}" in
        no|prohibit-password|forced-commands-only)
            FINDINGS+=("PASS: PermitRootLogin = ${VAL}") ;;
        yes)
            if [[ "$ALLOW_ROOT_LOGIN" == "false" ]]; then
                FINDINGS+=("FAIL: PermitRootLogin = yes (root SSH login is allowed)")
                STATUS="fail"
            else
                FINDINGS+=("INFO: PermitRootLogin = yes (allowed by config)")
            fi ;;
        *) FINDINGS+=("INFO: PermitRootLogin = ${VAL}") ;;
    esac
else
    FINDINGS+=("WARN: PermitRootLogin not explicitly set")
    [[ "$STATUS" == "pass" ]] && STATUS="warn"
fi

# ---------- PasswordAuthentication ----------
VAL=$(get_setting PasswordAuthentication)
if [[ -n "$VAL" ]]; then
    if [[ "${VAL,,}" == "no" ]]; then
        FINDINGS+=("PASS: PasswordAuthentication = no (key-based only)")
    elif [[ "${VAL,,}" == "yes" && "$ALLOW_PASSWORD_AUTH" == "false" ]]; then
        FINDINGS+=("WARN: PasswordAuthentication = yes (password login allowed)")
        [[ "$STATUS" == "pass" ]] && STATUS="warn"
    fi
else
    FINDINGS+=("WARN: PasswordAuthentication not explicitly set")
    [[ "$STATUS" == "pass" ]] && STATUS="warn"
fi

# ---------- Protocol ----------
VAL=$(get_setting Protocol)
if [[ -n "$VAL" ]]; then
    if [[ "$VAL" == "2" ]]; then
        FINDINGS+=("PASS: Protocol = 2")
    else
        FINDINGS+=("FAIL: Protocol = ${VAL} (should be 2)")
        [[ "$REQUIRE_PROTOCOL2" == "true" ]] && STATUS="fail"
    fi
else
    FINDINGS+=("INFO: Protocol not set (SSH2 is default in modern OpenSSH)")
fi

# ---------- MaxAuthTries ----------
VAL=$(get_setting MaxAuthTries)
if [[ -n "$VAL" ]]; then
    if (( VAL <= MAX_AUTH_TRIES )); then
        FINDINGS+=("PASS: MaxAuthTries = ${VAL}")
    else
        FINDINGS+=("WARN: MaxAuthTries = ${VAL} (recommended: ${MAX_AUTH_TRIES})")
        [[ "$STATUS" == "pass" ]] && STATUS="warn"
    fi
else
    FINDINGS+=("WARN: MaxAuthTries not set (default is 6)")
    [[ "$STATUS" == "pass" ]] && STATUS="warn"
fi

# ---------- X11Forwarding ----------
VAL=$(get_setting X11Forwarding)
if [[ "${VAL,,}" == "yes" ]]; then
    FINDINGS+=("WARN: X11Forwarding = yes (consider disabling if not needed)")
    [[ "$STATUS" == "pass" ]] && STATUS="warn"
else
    FINDINGS+=("PASS: X11Forwarding is not enabled")
fi

# ---------- PermitEmptyPasswords ----------
VAL=$(get_setting PermitEmptyPasswords)
if [[ "${VAL,,}" == "yes" ]]; then
    FINDINGS+=("FAIL: PermitEmptyPasswords = yes — critical risk!")
    STATUS="fail"
else
    FINDINGS+=("PASS: PermitEmptyPasswords is not enabled")
fi

# ---------- AllowTcpForwarding ----------
VAL=$(get_setting AllowTcpForwarding)
if [[ "${VAL,,}" == "yes" ]]; then
    FINDINGS+=("WARN: AllowTcpForwarding = yes (consider disabling if not needed)")
fi

# ---------- LoginGraceTime ----------
VAL=$(get_setting LoginGraceTime)
[[ -n "$VAL" ]] && FINDINGS+=("INFO: LoginGraceTime = ${VAL}")

# ---------- UsePAM ----------
VAL=$(get_setting UsePAM)
[[ "${VAL,,}" == "yes" ]] && FINDINGS+=("PASS: UsePAM = yes")

# ---------- ClientAliveInterval ----------
VAL=$(get_setting ClientAliveInterval)
if [[ -n "$VAL" && "$VAL" -gt 0 ]]; then
    FINDINGS+=("PASS: ClientAliveInterval = ${VAL} (idle timeout is set)")
else
    FINDINGS+=("WARN: ClientAliveInterval not set (no SSH idle timeout)")
    [[ "$STATUS" == "pass" ]] && STATUS="warn"
fi

echo ""
echo "=== SSH Configuration Check ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
