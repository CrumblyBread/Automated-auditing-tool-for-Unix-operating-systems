#!/usr/bin/env bash
# ============================================================
# openPortsCheck.sh — Open Ports Check
# Params (env vars):
#   ALLOWED_PORTS         (default: "22 80 443" — space-separated)
#   WARN_ON_UNEXPECTED    (default: true)
#   CHECK_UDP             (default: false)
# ============================================================

ALLOWED_PORTS="${ALLOWED_PORTS:-22 80 443}"
WARN_ON_UNEXPECTED="${WARN_ON_UNEXPECTED:-true}"
CHECK_UDP="${CHECK_UDP:-false}"

STATUS="pass"
FINDINGS=()

# Build an associative set for O(1) lookup
declare -A ALLOWED_SET
for p in $ALLOWED_PORTS; do ALLOWED_SET[$p]=1; done

# Sensitive ports
declare -A SENSITIVE_PORTS=(
    [21]="FTP" [23]="Telnet" [25]="SMTP" [110]="POP3" [143]="IMAP"
    [3306]="MySQL" [5432]="PostgreSQL" [27017]="MongoDB" [6379]="Redis"
    [11211]="Memcached" [9200]="Elasticsearch" [2375]="Docker (unencrypted)"
    [5900]="VNC" [1521]="Oracle DB" [1433]="MSSQL"
)

parse_ports() {
    # $1 = output of ss -tlnp / ss -ulnp
    echo "$1" | awk 'NR>1 {
        split($5, a, ":")
        port = a[length(a)]
        if (port ~ /^[0-9]+$/) print port
    }' | sort -un
}

TCP_OUT=""
UDP_OUT=""

if command -v ss &>/dev/null; then
    TCP_OUT=$(ss -tlnp 2>/dev/null)
    [[ "$CHECK_UDP" == "true" ]] && UDP_OUT=$(ss -ulnp 2>/dev/null)
elif command -v netstat &>/dev/null; then
    TCP_OUT=$(netstat -tlnp 2>/dev/null)
    [[ "$CHECK_UDP" == "true" ]] && UDP_OUT=$(netstat -ulnp 2>/dev/null)
else
    FINDINGS+=("ERROR: Neither ss nor netstat available")
    echo "=== Open Ports Check ==="
    echo "Status: error"
    echo "  ${FINDINGS[0]}"
    exit 1
fi

TCP_PORTS=$(parse_ports "$TCP_OUT")
UDP_PORTS=$( [[ "$CHECK_UDP" == "true" ]] && parse_ports "$UDP_OUT" || echo "")

ALL_PORTS=$(printf "%s\n%s" "$TCP_PORTS" "$UDP_PORTS" | grep -v '^$' | sort -un)

echo "[*] Open listening ports detected:"

OPEN_COUNT=0
while IFS= read -r port; do
    [[ -z "$port" ]] && continue
    (( OPEN_COUNT++ ))

    PROTO="TCP"
    echo "$UDP_PORTS" | grep -qx "$port" && PROTO="UDP"

    if [[ "${ALLOWED_SET[$port]+_}" ]]; then
        FINDINGS+=("PASS: Port ${port}/${PROTO} is open and in the allowed list")
    else
        FINDINGS+=("WARN: Port ${port}/${PROTO} is open but NOT in the allowed list")
        [[ "$WARN_ON_UNEXPECTED" == "true" && "$STATUS" == "pass" ]] && STATUS="warn"
    fi

    # Flag sensitive ports
    if [[ "${SENSITIVE_PORTS[$port]+_}" ]]; then
        FINDINGS+=("WARN: Sensitive service port — ${port} (${SENSITIVE_PORTS[$port]})")
        [[ "$STATUS" == "pass" ]] && STATUS="warn"
    fi
done <<< "$ALL_PORTS"

FINDINGS+=("INFO: Total open listening ports: ${OPEN_COUNT}")
[[ $OPEN_COUNT -eq 0 ]] && FINDINGS+=("INFO: No listening ports detected")

echo ""
echo "=== Open Ports Check ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
