#!/usr/bin/env bash
# ============================================================
# servicesAuditCheck.sh — Running Services Audit
# Params (env vars):
#   CHECK_UNNECESSARY      (default: true)
#   UNNECESSARY_SERVICES   (default: known legacy/insecure list — space-separated)
# ============================================================

CHECK_UNNECESSARY="${CHECK_UNNECESSARY:-true}"
UNNECESSARY_SERVICES="${UNNECESSARY_SERVICES:-telnet rsh rlogin rexec finger talk ntalk \
chargen daytime discard echo time avahi-daemon cups \
isc-dhcp-server slapd nfs-server nis rpcbind snmpd \
vsftpd proftpd pure-ftpd xinetd}"

STATUS="pass"
FINDINGS=()
RUNNING_SERVICES=()

# ---------- enumerate running services ----------
if command -v systemctl &>/dev/null; then
    while IFS= read -r line; do
        svc=$(echo "$line" | awk '{print $1}' | sed 's/\.service$//')
        RUNNING_SERVICES+=("$svc")
    done < <(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null)
    echo "[*] Found ${#RUNNING_SERVICES[@]} running services via systemctl"
elif command -v service &>/dev/null; then
    while IFS= read -r line; do
        if [[ "$line" == *"[ + ]"* ]]; then
            svc=$(echo "$line" | awk '{print $NF}')
            RUNNING_SERVICES+=("$svc")
        fi
    done < <(service --status-all 2>&1)
    echo "[*] Found ${#RUNNING_SERVICES[@]} running services via service --status-all"
else
    FINDINGS+=("WARN: Could not enumerate running services (no systemctl or service)")
    echo "=== Running Services Audit ==="
    echo "Status: warn"
    echo "  ${FINDINGS[0]}"
    exit 0
fi

FINDINGS+=("INFO: ${#RUNNING_SERVICES[@]} services currently running")

# ---------- unnecessary services ----------
if [[ "$CHECK_UNNECESSARY" == "true" ]]; then
    for svc in "${RUNNING_SERVICES[@]}"; do
        for bad in $UNNECESSARY_SERVICES; do
            if [[ "$svc" == *"$bad"* ]]; then
                FINDINGS+=("WARN: Potentially unnecessary service running: ${svc}")
                [[ "$STATUS" == "pass" ]] && STATUS="warn"
                break
            fi
        done
    done
fi

# ---------- dangerous / cleartext protocol services ----------
declare -A DANGEROUS=(
    ["telnet"]="Telnet (cleartext remote access)"
    ["ftp"]="FTP (cleartext file transfer)"
    ["rsh"]="RSH (cleartext remote shell)"
    ["rlogin"]="Rlogin (cleartext remote login)"
    ["finger"]="Finger (user info disclosure)"
    ["vnc"]="VNC (check if exposed externally)"
)

for svc in "${RUNNING_SERVICES[@]}"; do
    for keyword in "${!DANGEROUS[@]}"; do
        if [[ "${svc,,}" == *"$keyword"* ]]; then
            FINDINGS+=("FAIL: Dangerous service detected: ${svc} — ${DANGEROUS[$keyword]}")
            STATUS="fail"
            break
        fi
    done
done

# ---------- services listening on all interfaces ----------
if command -v ss &>/dev/null; then
    while IFS= read -r line; do
        # Lines with 0.0.0.0: or :::
        if echo "$line" | grep -qE '(0\.0\.0\.0|::):'; then
            PORT=$(echo "$line" | awk '{print $5}' | grep -oP ':\K\d+$')
            [[ -n "$PORT" ]] && FINDINGS+=("INFO: Service listening on all interfaces — port ${PORT}")
        fi
    done < <(ss -tlnp 2>/dev/null | tail -n +2)
fi

[[ "$STATUS" == "pass" ]] && FINDINGS+=("PASS: No unnecessary or dangerous services detected")

echo ""
echo "=== Running Services Audit ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
