#!/usr/bin/env bash
# ============================================================
# firewallCheck.sh — Firewall Status Check
# Params (env vars):
#   REQUIRE_ACTIVE   (default: true)
#   CHECK_RULES      (default: true)
# ============================================================

REQUIRE_ACTIVE="${REQUIRE_ACTIVE:-true}"
CHECK_RULES="${CHECK_RULES:-true}"

STATUS="pass"
FINDINGS=()

UFW_FOUND=false
IPTABLES_FOUND=false
ACTIVE=false

# ---------- UFW ----------
if command -v ufw &>/dev/null; then
    UFW_FOUND=true
    UFW_STATUS=$(ufw status verbose 2>/dev/null)
    echo "[*] UFW found"
    if echo "$UFW_STATUS" | grep -q "Status: active"; then
        FINDINGS+=("PASS: UFW firewall is active")
        ACTIVE=true
        if [[ "$CHECK_RULES" == "true" ]]; then
            RULE_COUNT=$(echo "$UFW_STATUS" | grep -c "ALLOW\|DENY\|REJECT\|LIMIT" || true)
            FINDINGS+=("INFO: UFW has ${RULE_COUNT} rule(s) configured")
        fi
    else
        FINDINGS+=("FAIL: UFW is installed but NOT active")
        [[ "$REQUIRE_ACTIVE" == "true" ]] && STATUS="fail"
    fi
else
    FINDINGS+=("INFO: UFW not installed")
fi

# ---------- iptables ----------
if command -v iptables &>/dev/null; then
    IPTABLES_FOUND=true
    RULE_LINES=$(iptables -L -n --line-numbers 2>/dev/null | grep -c "^[0-9]" || true)
    echo "[*] iptables found — ${RULE_LINES} numbered rule(s)"
    if (( RULE_LINES > 0 )); then
        FINDINGS+=("PASS: iptables has ${RULE_LINES} rule(s) active")
        ACTIVE=true
    else
        FINDINGS+=("INFO: iptables present but no custom rules found (only defaults)")
    fi

    # Check INPUT policy
    INPUT_POLICY=$(iptables -L INPUT 2>/dev/null | head -1 | awk '{print $NF}' | tr -d ')')
    FINDINGS+=("INFO: iptables INPUT default policy: ${INPUT_POLICY:-unknown}")
    if [[ "$INPUT_POLICY" == "DROP" || "$INPUT_POLICY" == "REJECT" ]]; then
        FINDINGS+=("PASS: iptables INPUT default policy is restrictive (${INPUT_POLICY})")
    else
        FINDINGS+=("WARN: iptables INPUT default policy is ${INPUT_POLICY:-unknown} (consider DROP)")
        [[ "$STATUS" == "pass" ]] && STATUS="warn"
    fi
else
    FINDINGS+=("INFO: iptables not installed")
fi

# ---------- nftables ----------
if command -v nft &>/dev/null; then
    NFT_OUT=$(nft list ruleset 2>/dev/null)
    if [[ -n "$NFT_OUT" ]]; then
        FINDINGS+=("INFO: nftables ruleset is present")
        ACTIVE=true
    else
        FINDINGS+=("INFO: nftables installed but ruleset is empty")
    fi
else
    FINDINGS+=("INFO: nftables not installed")
fi

# ---------- firewalld ----------
if command -v firewall-cmd &>/dev/null; then
    FWD_STATE=$(firewall-cmd --state 2>/dev/null)
    if [[ "$FWD_STATE" == "running" ]]; then
        FINDINGS+=("PASS: firewalld is running")
        ACTIVE=true
    else
        FINDINGS+=("INFO: firewalld installed but not running (${FWD_STATE})")
    fi
fi

# ---------- final verdict ----------
if [[ "$ACTIVE" == "false" ]]; then
    FINDINGS+=("FAIL: No firewall appears to be active on this system")
    [[ "$REQUIRE_ACTIVE" == "true" ]] && STATUS="fail"
fi

echo ""
echo "=== Firewall Status Check ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
