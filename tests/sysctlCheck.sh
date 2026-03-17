#!/usr/bin/env bash
# ============================================================
# sysctlCheck.sh — Sysctl Kernel Security Parameters Check
# Params (env vars):
#   STRICT_MODE   (default: false)
#     When true, any mismatch is treated as FAIL instead of WARN
# ============================================================

STRICT_MODE="${STRICT_MODE:-false}"

STATUS="pass"
FINDINGS=()

if ! command -v sysctl &>/dev/null; then
    echo "ERROR: sysctl not available"
    exit 1
fi

# Format: "key|expected_value|description|is_critical"
CHECKS=(
    "kernel.randomize_va_space|2|ASLR fully enabled|critical"
    "net.ipv4.ip_forward|0|IP forwarding disabled|normal"
    "net.ipv4.conf.all.send_redirects|0|ICMP send redirects disabled|normal"
    "net.ipv4.conf.default.send_redirects|0|ICMP send redirects disabled (default)|normal"
    "net.ipv4.conf.all.accept_redirects|0|ICMP accept redirects disabled|normal"
    "net.ipv4.conf.default.accept_redirects|0|ICMP accept redirects disabled (default)|normal"
    "net.ipv4.conf.all.accept_source_route|0|Source routing disabled|critical"
    "net.ipv4.conf.all.log_martians|1|Martian packet logging enabled|normal"
    "net.ipv4.tcp_syncookies|1|SYN flood protection enabled|critical"
    "net.ipv4.icmp_echo_ignore_broadcasts|1|ICMP broadcast echo disabled|normal"
    "net.ipv4.icmp_ignore_bogus_error_responses|1|Bogus ICMP errors ignored|normal"
    "kernel.dmesg_restrict|1|dmesg restricted to root|normal"
    "kernel.kptr_restrict|2|Kernel pointer leak restricted|normal"
    "kernel.sysrq|0|SysRq key disabled|normal"
    "kernel.core_uses_pid|1|Core dumps use PID|normal"
    "net.ipv6.conf.all.accept_redirects|0|IPv6 ICMP redirects not accepted|normal"
    "net.ipv6.conf.all.accept_ra|0|IPv6 router advertisements disabled|normal"
    "fs.suid_dumpable|0|SUID core dumps disabled|critical"
    "fs.protected_hardlinks|1|Hardlink protection enabled|critical"
    "fs.protected_symlinks|1|Symlink protection enabled|critical"
)

for check in "${CHECKS[@]}"; do
    IFS='|' read -r key expected desc criticality <<< "$check"
    VAL=$(sysctl -n "$key" 2>/dev/null)

    if [[ -z "$VAL" ]]; then
        FINDINGS+=("INFO: ${key} — not available on this system")
        continue
    fi

    # Trim whitespace
    VAL="${VAL// /}"

    if [[ "$VAL" == "$expected" ]]; then
        FINDINGS+=("PASS: ${key} = ${VAL} (${desc})")
    else
        if [[ "$criticality" == "critical" || "$STRICT_MODE" == "true" ]]; then
            FINDINGS+=("FAIL: ${key} = ${VAL} (expected ${expected}) — ${desc}")
            STATUS="fail"
        else
            FINDINGS+=("WARN: ${key} = ${VAL} (expected ${expected}) — ${desc}")
            [[ "$STATUS" == "pass" ]] && STATUS="warn"
        fi
    fi
done

echo ""
echo "=== Sysctl Security Parameters Check ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
