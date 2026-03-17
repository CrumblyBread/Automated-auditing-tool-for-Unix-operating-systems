#!/usr/bin/env bash
# ============================================================
# auditLoggingCheck.sh — Audit Logging Configuration Check
# Params (env vars):
#   REQUIRE_AUDITD       (default: true)
#   CHECK_LOG_ROTATION   (default: true)
#   CHECK_SYSLOG         (default: true)
# ============================================================

REQUIRE_AUDITD="${REQUIRE_AUDITD:-true}"
CHECK_LOG_ROTATION="${CHECK_LOG_ROTATION:-true}"
CHECK_SYSLOG="${CHECK_SYSLOG:-true}"

STATUS="pass"
FINDINGS=()

is_service_active() {
    systemctl is-active "$1" 2>/dev/null | grep -q "^active"
}

# ---------- auditd ----------
AUDITD_ACTIVE=false
if command -v systemctl &>/dev/null; then
    if is_service_active auditd; then
        FINDINGS+=("PASS: auditd is active")
        AUDITD_ACTIVE=true
    else
        FINDINGS+=("WARN: auditd is not active")
        if [[ "$REQUIRE_AUDITD" == "true" ]]; then
            STATUS="fail"
        else
            [[ "$STATUS" == "pass" ]] && STATUS="warn"
        fi
    fi
else
    if pgrep -x auditd &>/dev/null; then
        FINDINGS+=("PASS: auditd process is running")
        AUDITD_ACTIVE=true
    else
        FINDINGS+=("WARN: auditd does not appear to be running")
        [[ "$REQUIRE_AUDITD" == "true" ]] && STATUS="fail"
    fi
fi

# ---------- auditd rules ----------
if [[ "$AUDITD_ACTIVE" == "true" ]] && command -v auditctl &>/dev/null; then
    RULE_OUTPUT=$(auditctl -l 2>/dev/null)
    RULE_COUNT=$(echo "$RULE_OUTPUT" | grep -vc 'No rules\|^$' || true)

    if (( RULE_COUNT > 0 )); then
        FINDINGS+=("PASS: ${RULE_COUNT} audit rule(s) configured")
    else
        FINDINGS+=("WARN: auditd running but no rules configured")
        [[ "$STATUS" == "pass" ]] && STATUS="warn"
    fi

    # Key rules to check for
    IMPORTANT_RULES=("-w /etc/passwd" "-w /etc/shadow" "-w /etc/sudoers" "-w /var/log/auth.log")
    for rule in "${IMPORTANT_RULES[@]}"; do
        if echo "$RULE_OUTPUT" | grep -qF -- "$rule"; then
            FINDINGS+=("PASS: Audit rule present: ${rule}")
        else
            FINDINGS+=("INFO: Audit rule not found: ${rule}")
        fi
    done
fi

# ---------- syslog ----------
if [[ "$CHECK_SYSLOG" == "true" ]]; then
    SYSLOG_FOUND=false
    for svc in rsyslog syslog systemd-journald syslog-ng; do
        if command -v systemctl &>/dev/null && is_service_active "$svc"; then
            FINDINGS+=("PASS: ${svc} is active")
            SYSLOG_FOUND=true
        elif pgrep -x "$svc" &>/dev/null; then
            FINDINGS+=("PASS: ${svc} process running")
            SYSLOG_FOUND=true
        fi
    done
    if [[ "$SYSLOG_FOUND" == "false" ]]; then
        FINDINGS+=("WARN: No syslog service detected (rsyslog, syslog-ng, journald)")
        [[ "$STATUS" == "pass" ]] && STATUS="warn"
    fi
fi

# ---------- log files ----------
LOG_FILES=("/var/log/auth.log" "/var/log/syslog" "/var/log/messages" "/var/log/kern.log" "/var/log/secure")
for lf in "${LOG_FILES[@]}"; do
    if [[ -f "$lf" ]]; then
        SIZE=$(du -sh "$lf" 2>/dev/null | awk '{print $1}')
        FINDINGS+=("INFO: Log file present: ${lf} (${SIZE})")
    fi
done

# ---------- log rotation ----------
if [[ "$CHECK_LOG_ROTATION" == "true" ]]; then
    if [[ -f /etc/logrotate.conf ]]; then
        FINDINGS+=("PASS: /etc/logrotate.conf present")
    else
        FINDINGS+=("WARN: /etc/logrotate.conf not found")
        [[ "$STATUS" == "pass" ]] && STATUS="warn"
    fi
    if [[ -d /etc/logrotate.d ]]; then
        COUNT=$(find /etc/logrotate.d -type f 2>/dev/null | wc -l)
        FINDINGS+=("INFO: ${COUNT} logrotate.d config(s) found")
    fi
fi

echo ""
echo "=== Audit Logging Configuration ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
