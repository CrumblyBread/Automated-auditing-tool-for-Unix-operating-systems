#!/usr/bin/env bash
# ============================================================
# securityUpdatesCheck.sh — Pending Updates Check
# Params (env vars):
#   MAX_UPDATES_WARNING   (default: 10)
#   MAX_UPDATES_CRITICAL  (default: 50)
#   CHECK_SECURITY_ONLY   (default: false)
# ============================================================

MAX_UPDATES_WARNING="${MAX_UPDATES_WARNING:-10}"
MAX_UPDATES_CRITICAL="${MAX_UPDATES_CRITICAL:-50}"
CHECK_SECURITY_ONLY="${CHECK_SECURITY_ONLY:-false}"

STATUS="pass"
FINDINGS=()
COUNT=0

# ---------- apt (Debian/Ubuntu) ----------
if command -v apt-get &>/dev/null; then
    echo "[*] Updating package lists..."
    apt-get update -qq 2>/dev/null

    if [[ "$CHECK_SECURITY_ONLY" == "true" ]]; then
        COUNT=$(apt-get --simulate upgrade 2>/dev/null \
            | grep '^Inst' \
            | grep -i security \
            | wc -l)
        FINDINGS+=("INFO: ${COUNT} security-only updates pending")
    else
        COUNT=$(apt-get --simulate upgrade 2>/dev/null \
            | grep '^Inst' \
            | wc -l)
        FINDINGS+=("INFO: ${COUNT} total updates pending")
    fi

    # List first 10 packages
    PKGS=$(apt-get --simulate upgrade 2>/dev/null | grep '^Inst' | head -10 | awk '{print $2}')
    while IFS= read -r pkg; do
        [[ -n "$pkg" ]] && FINDINGS+=("  Package: ${pkg}")
    done <<< "$PKGS"

    if (( COUNT > MAX_UPDATES_WARNING )); then
        FINDINGS+=("  ... and more")
    fi

# ---------- yum/dnf (RHEL/CentOS/Fedora) ----------
elif command -v yum &>/dev/null || command -v dnf &>/dev/null; then
    PKG_MGR=$(command -v dnf || command -v yum)
    echo "[*] Using ${PKG_MGR}"
    COUNT=$("$PKG_MGR" check-update --quiet 2>/dev/null | grep -c '^\S' || true)
    FINDINGS+=("INFO: ${COUNT} updates available via $(basename $PKG_MGR)")

# ---------- zypper (openSUSE) ----------
elif command -v zypper &>/dev/null; then
    COUNT=$(zypper list-updates 2>/dev/null | grep -c '^|' || true)
    FINDINGS+=("INFO: ${COUNT} updates available via zypper")

else
    FINDINGS+=("WARN: No supported package manager found (apt/yum/dnf/zypper)")
    STATUS="warn"
    COUNT=-1
fi

# ---------- thresholds ----------
if (( COUNT == 0 )); then
    FINDINGS+=("PASS: System is fully up to date")
elif (( COUNT <= MAX_UPDATES_WARNING )); then
    FINDINGS+=("WARN: ${COUNT} updates pending (warning threshold: ${MAX_UPDATES_WARNING})")
    STATUS="warn"
elif (( COUNT <= MAX_UPDATES_CRITICAL )); then
    FINDINGS+=("FAIL: ${COUNT} updates pending — exceeds warning threshold (${MAX_UPDATES_WARNING})")
    STATUS="fail"
elif (( COUNT > MAX_UPDATES_CRITICAL )); then
    FINDINGS+=("CRITICAL: ${COUNT} updates pending — exceeds critical threshold (${MAX_UPDATES_CRITICAL})")
    STATUS="critical"
fi

echo ""
echo "=== Security Updates Check ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
