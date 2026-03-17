#!/usr/bin/env bash
# ============================================================
# macSystemcheck.sh — MAC System Check (AppArmor / SELinux)
# Params (env vars):
#   PREFERRED_MAC    (default: apparmor)
#   REQUIRE_ACTIVE   (default: true)
#   CHECK_PROFILES   (default: true)
# ============================================================

PREFERRED_MAC="${PREFERRED_MAC:-apparmor}"
REQUIRE_ACTIVE="${REQUIRE_ACTIVE:-true}"
CHECK_PROFILES="${CHECK_PROFILES:-true}"

STATUS="pass"
FINDINGS=()
APPARMOR_ACTIVE=false
SELINUX_ACTIVE=false

# ---------- AppArmor ----------
if command -v aa-status &>/dev/null; then
    if aa-status --enabled 2>/dev/null; then
        APPARMOR_ACTIVE=true
        FINDINGS+=("PASS: AppArmor is enabled")

        if [[ "$CHECK_PROFILES" == "true" ]]; then
            AA_OUT=$(aa-status 2>/dev/null)
            ENFORCE=$(echo "$AA_OUT" | grep -oP '^\s*\K\d+(?= profiles are in enforce mode)' || echo "0")
            COMPLAIN=$(echo "$AA_OUT" | grep -oP '^\s*\K\d+(?= profiles are in complain mode)' || echo "0")
            FINDINGS+=("INFO: AppArmor — enforcing: ${ENFORCE}, complain: ${COMPLAIN}")
            if (( COMPLAIN > 0 )); then
                FINDINGS+=("WARN: ${COMPLAIN} profile(s) in complain mode (not enforcing)")
                [[ "$STATUS" == "pass" ]] && STATUS="warn"
            fi
        fi
    else
        FINDINGS+=("INFO: AppArmor installed but not enabled")
    fi
else
    FINDINGS+=("INFO: AppArmor not installed (aa-status not found)")
fi

# ---------- SELinux ----------
if command -v getenforce &>/dev/null; then
    SE_MODE=$(getenforce 2>/dev/null)
    if [[ -n "$SE_MODE" ]]; then
        SELINUX_ACTIVE=true
        FINDINGS+=("INFO: SELinux mode: ${SE_MODE}")
        case "$SE_MODE" in
            Enforcing)
                FINDINGS+=("PASS: SELinux is Enforcing") ;;
            Permissive)
                FINDINGS+=("WARN: SELinux is Permissive (not enforcing)")
                [[ "$STATUS" == "pass" ]] && STATUS="warn" ;;
            Disabled)
                FINDINGS+=("INFO: SELinux is Disabled")
                SELINUX_ACTIVE=false ;;
        esac
    fi
else
    FINDINGS+=("INFO: SELinux not installed (getenforce not found)")
fi

# ---------- final verdict ----------
if [[ "$APPARMOR_ACTIVE" == "false" && "$SELINUX_ACTIVE" == "false" ]]; then
    FINDINGS+=("FAIL: No MAC system (AppArmor/SELinux) is active")
    [[ "$REQUIRE_ACTIVE" == "true" ]] && STATUS="fail"
fi

if [[ "$PREFERRED_MAC" == "apparmor" && "$APPARMOR_ACTIVE" == "false" ]]; then
    FINDINGS+=("WARN: Preferred MAC system 'apparmor' is not active")
    [[ "$STATUS" == "pass" ]] && STATUS="warn"
elif [[ "$PREFERRED_MAC" == "selinux" && "$SELINUX_ACTIVE" == "false" ]]; then
    FINDINGS+=("WARN: Preferred MAC system 'selinux' is not active")
    [[ "$STATUS" == "pass" ]] && STATUS="warn"
fi

echo ""
echo "=== MAC System Check ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
