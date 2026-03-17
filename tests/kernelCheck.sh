#!/usr/bin/env bash
# ============================================================
# kernelCheck.sh — Kernel Version Check
# Params (env vars):
#   MIN_KERNEL_VERSION  (default: 5.4.0)
# ============================================================

MIN_KERNEL_VERSION="${MIN_KERNEL_VERSION:-5.4.0}"

STATUS="pass"
FINDINGS=()

version_gte() {
    local IFS=.
    local -a cur=($1) min=($2)
    for i in 0 1 2; do
        local a="${cur[$i]:-0}"; a="${a%%[^0-9]*}"
        local b="${min[$i]:-0}"; b="${b%%[^0-9]*}"
        (( 10#$a > 10#$b )) && return 0
        (( 10#$a < 10#$b )) && return 1
    done
    return 0
}

KERNEL=$(uname -r)
echo "[*] Detected kernel: ${KERNEL}"

KERNEL_VER=$(echo "$KERNEL" | grep -oP '^\d+\.\d+\.\d+')

if [[ -z "$KERNEL_VER" ]]; then
    FINDINGS+=("ERROR: Could not parse kernel version from '${KERNEL}'")
    STATUS="error"
else
    if version_gte "$KERNEL_VER" "$MIN_KERNEL_VERSION"; then
        FINDINGS+=("PASS: Kernel ${KERNEL} meets minimum version ${MIN_KERNEL_VERSION}")
    else
        FINDINGS+=("FAIL: Kernel ${KERNEL} is below minimum required ${MIN_KERNEL_VERSION}")
        STATUS="fail"
    fi
fi

FINDINGS+=("INFO: uname -r: $(uname -r)")
FINDINGS+=("INFO: uname -v: $(uname -v)")

echo ""
echo "=== Kernel Version Check ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
