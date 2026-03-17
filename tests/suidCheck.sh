#!/usr/bin/env bash
# ============================================================
# suidCheck.sh — SUID/SGID Files Check
# Params (env vars):
#   SCAN_PATHS            (default: "/usr /bin /sbin" — space-separated)
#   KNOWN_SUID_WHITELIST  (default: common safe binaries — space-separated)
# ============================================================

SCAN_PATHS="${SCAN_PATHS:-/usr /bin /sbin}"

KNOWN_SUID_WHITELIST="${KNOWN_SUID_WHITELIST:-\
/usr/bin/sudo /usr/bin/su /usr/bin/passwd /usr/bin/gpasswd \
/usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp /usr/bin/pkexec \
/usr/bin/mount /usr/bin/umount /bin/mount /bin/umount \
/bin/su /bin/ping /usr/bin/ping /usr/sbin/pppd \
/usr/lib/openssh/ssh-keysign \
/usr/lib/dbus-1.0/dbus-daemon-launch-helper}"

STATUS="pass"
FINDINGS=()

# Build whitelist lookup
declare -A WL
for item in $KNOWN_SUID_WHITELIST; do WL[$item]=1; done

SUID_FILES=()
SGID_FILES=()

echo "[*] Scanning for SUID/SGID files in: ${SCAN_PATHS}"

while IFS= read -r filepath; do
    [[ -z "$filepath" ]] && continue
    PERMS=$(stat -c "%a" "$filepath" 2>/dev/null) || continue
    # SUID bit = 4000, SGID bit = 2000
    SPECIAL=$(( 8#$PERMS >> 9 & 7 ))
    if (( SPECIAL & 4 )); then
        SUID_FILES+=("$filepath")
    elif (( SPECIAL & 2 )); then
        SGID_FILES+=("$filepath")
    fi
done < <(find $SCAN_PATHS \( -perm /4000 -o -perm /2000 \) -type f 2>/dev/null)

echo "[*] Found ${#SUID_FILES[@]} SUID and ${#SGID_FILES[@]} SGID files"

FINDINGS+=("INFO: ${#SUID_FILES[@]} SUID and ${#SGID_FILES[@]} SGID files found")

for f in "${SUID_FILES[@]}"; do
    if [[ "${WL[$f]+_}" ]]; then
        FINDINGS+=("INFO: Known/expected SUID binary: ${f}")
    else
        FINDINGS+=("WARN: Unknown SUID binary found: ${f}")
        [[ "$STATUS" == "pass" ]] && STATUS="warn"
    fi
done

for f in "${SGID_FILES[@]}"; do
    FINDINGS+=("INFO: SGID file: ${f}")
done

[[ "$STATUS" == "pass" ]] && FINDINGS+=("PASS: All SUID binaries are on the known whitelist")

echo ""
echo "=== SUID/SGID Files Check ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
