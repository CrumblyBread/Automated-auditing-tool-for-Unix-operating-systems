#!/usr/bin/env bash
# ============================================================
# diskEncryptionCheck.sh — Disk Encryption Check
# Params (env vars):
#   REQUIRE_ROOT_ENCRYPTED   (default: false)
#   CHECK_SWAP_ENCRYPTED     (default: true)
# ============================================================

REQUIRE_ROOT_ENCRYPTED="${REQUIRE_ROOT_ENCRYPTED:-false}"
CHECK_SWAP_ENCRYPTED="${CHECK_SWAP_ENCRYPTED:-true}"

STATUS="pass"
FINDINGS=()
LUKS_DEVICES=()

# ---------- LUKS via lsblk ----------
if command -v lsblk &>/dev/null; then
    while IFS= read -r line; do
        TYPE=$(echo "$line" | awk '{print $2}')
        NAME=$(echo "$line" | awk '{print $1}' | tr -d '`├└─')
        if [[ "$TYPE" == "crypt" ]]; then
            LUKS_DEVICES+=("$NAME")
        fi
    done < <(lsblk -o NAME,TYPE 2>/dev/null | tail -n +2)

    if (( ${#LUKS_DEVICES[@]} > 0 )); then
        FINDINGS+=("PASS: LUKS/dm-crypt device(s) detected: ${LUKS_DEVICES[*]}")
    else
        FINDINGS+=("INFO: No LUKS encrypted devices detected via lsblk")
    fi
fi

# ---------- dmsetup fallback ----------
if (( ${#LUKS_DEVICES[@]} == 0 )) && command -v dmsetup &>/dev/null; then
    DM_CRYPT=$(dmsetup ls --target crypt 2>/dev/null | grep -v 'No devices')
    if [[ -n "$DM_CRYPT" ]]; then
        while IFS= read -r line; do
            NAME=$(echo "$line" | awk '{print $1}')
            LUKS_DEVICES+=("$NAME")
        done <<< "$DM_CRYPT"
        FINDINGS+=("PASS: dm-crypt device(s) found: ${LUKS_DEVICES[*]}")
    else
        FINDINGS+=("INFO: No dm-crypt devices found via dmsetup")
    fi
fi

# ---------- root filesystem ----------
ROOT_DEV=$(df / 2>/dev/null | tail -1 | awk '{print $1}')
FINDINGS+=("INFO: Root filesystem device: ${ROOT_DEV}")

ROOT_ENCRYPTED=false
for ldev in "${LUKS_DEVICES[@]}"; do
    [[ "$ROOT_DEV" == *"$ldev"* ]] && ROOT_ENCRYPTED=true && break
done
[[ "$ROOT_DEV" == /dev/dm-* ]] && ROOT_ENCRYPTED=true

if [[ "$ROOT_ENCRYPTED" == "true" ]]; then
    FINDINGS+=("PASS: Root filesystem appears to be on an encrypted volume")
else
    if [[ "$REQUIRE_ROOT_ENCRYPTED" == "true" ]]; then
        FINDINGS+=("WARN: Root filesystem does not appear to be encrypted")
        [[ "$STATUS" == "pass" ]] && STATUS="warn"
    else
        FINDINGS+=("INFO: Root filesystem does not appear to be encrypted")
    fi
fi

# ---------- swap ----------
if [[ "$CHECK_SWAP_ENCRYPTED" == "true" ]]; then
    if [[ -f /proc/swaps ]]; then
        SWAP_LINES=$(tail -n +2 /proc/swaps)
        if [[ -z "$SWAP_LINES" ]]; then
            FINDINGS+=("INFO: No swap configured")
        else
            while IFS= read -r line; do
                SWAP_DEV=$(echo "$line" | awk '{print $1}')
                FINDINGS+=("INFO: Swap device: ${SWAP_DEV}")

                SWAP_ENCRYPTED=false
                for ldev in "${LUKS_DEVICES[@]}"; do
                    [[ "$SWAP_DEV" == *"$ldev"* ]] && SWAP_ENCRYPTED=true && break
                done
                [[ "$SWAP_DEV" == /dev/dm-* || "$SWAP_DEV" == *zram* ]] && SWAP_ENCRYPTED=true

                if [[ "$SWAP_ENCRYPTED" == "true" ]]; then
                    FINDINGS+=("PASS: Swap (${SWAP_DEV}) appears encrypted or compressed")
                else
                    FINDINGS+=("WARN: Swap (${SWAP_DEV}) may not be encrypted")
                    [[ "$STATUS" == "pass" ]] && STATUS="warn"
                fi
            done <<< "$SWAP_LINES"
        fi
    fi
fi

# ---------- ecryptfs ----------
ECRYPT=$(mount 2>/dev/null | grep ecryptfs)
if [[ -n "$ECRYPT" ]]; then
    COUNT=$(echo "$ECRYPT" | wc -l)
    FINDINGS+=("INFO: ecryptfs home directory encryption detected (${COUNT} mount(s))")
else
    FINDINGS+=("INFO: No ecryptfs home directory encryption detected")
fi

# ---------- /etc/crypttab ----------
if [[ -f /etc/crypttab ]]; then
    ENTRIES=$(grep -vc '^#\|^$' /etc/crypttab 2>/dev/null || true)
    FINDINGS+=("INFO: /etc/crypttab has ${ENTRIES} entry(ies)")
fi

echo ""
echo "=== Disk Encryption Check ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
