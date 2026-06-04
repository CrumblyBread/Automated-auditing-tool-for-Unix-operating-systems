#!/usr/bin/env bash
# ============================================================
# example.sh — Ukážkový / systémový informačný test
# Params (env vars):
#   VERBOSE  (default: false)
# ============================================================

VERBOSE="${VERBOSE:-false}"

STATUS="pass"
FINDINGS=()

FINDINGS+=("INFO: hostname: $(hostname 2>/dev/null || echo unknown)")
FINDINGS+=("INFO: kernel: $(uname -r 2>/dev/null || echo unknown)")
FINDINGS+=("INFO: os: $(uname -s 2>/dev/null || echo unknown) $(uname -m 2>/dev/null || echo)")

if [[ "$VERBOSE" == "true" ]]; then
    FINDINGS+=("INFO: verbose mode enabled")
    FINDINGS+=("INFO: uptime: $(uptime -p 2>/dev/null || uptime 2>/dev/null || echo n/a)")
fi

echo ""
echo "=== System Information ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
