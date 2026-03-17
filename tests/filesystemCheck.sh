#!/usr/bin/env bash
# ============================================================
# filesystemCheck.sh — Mounted Filesystem Security Check
# Params (env vars):
#   REQUIRE_NOEXEC_TMP          (default: true)
#   REQUIRE_NOSUID_REMOVABLE    (default: true)
#   CHECK_WORLD_WRITABLE_MOUNTS (default: true)
# ============================================================

REQUIRE_NOEXEC_TMP="${REQUIRE_NOEXEC_TMP:-true}"
REQUIRE_NOSUID_REMOVABLE="${REQUIRE_NOSUID_REMOVABLE:-true}"
CHECK_WORLD_WRITABLE_MOUNTS="${CHECK_WORLD_WRITABLE_MOUNTS:-true}"

STATUS="pass"
FINDINGS=()

check_mount_option() {
    # $1=mountpoint  $2=option  returns 0 if option present
    grep -E "^[^ ]+ ${1} " /proc/mounts 2>/dev/null | grep -qw "$2"
}

get_mount_options() {
    grep -E "^[^ ]+ ${1} " /proc/mounts 2>/dev/null | awk '{print $4}'
}

if [[ ! -f /proc/mounts ]]; then
    echo "ERROR: /proc/mounts not available"
    exit 1
fi

# ---------- /tmp ----------
if grep -qE '^[^ ]+ /tmp ' /proc/mounts; then
    TMP_OPTS=$(get_mount_options /tmp)
    echo "[*] /tmp is a separate mount: ${TMP_OPTS}"

    for opt in noexec nosuid nodev; do
        if echo "$TMP_OPTS" | grep -qw "$opt"; then
            FINDINGS+=("PASS: /tmp mounted with ${opt}")
        else
            FINDINGS+=("WARN: /tmp is NOT mounted with ${opt}")
            if [[ "$opt" == "noexec" && "$REQUIRE_NOEXEC_TMP" == "true" ]]; then
                [[ "$STATUS" == "pass" ]] && STATUS="warn"
            fi
        fi
    done
else
    FINDINGS+=("INFO: /tmp is not a separate mount point")
fi

# ---------- /var/tmp ----------
if grep -qE '^[^ ]+ /var/tmp ' /proc/mounts; then
    VTMP_OPTS=$(get_mount_options /var/tmp)
    echo "$VTMP_OPTS" | grep -qw noexec \
        && FINDINGS+=("PASS: /var/tmp mounted with noexec") \
        || { FINDINGS+=("WARN: /var/tmp not mounted with noexec"); [[ "$STATUS" == "pass" ]] && STATUS="warn"; }
fi

# ---------- /home ----------
if grep -qE '^[^ ]+ /home ' /proc/mounts; then
    HOME_OPTS=$(get_mount_options /home)
    for opt in nosuid nodev; do
        echo "$HOME_OPTS" | grep -qw "$opt" \
            && FINDINGS+=("PASS: /home mounted with ${opt}") \
            || { FINDINGS+=("WARN: /home not mounted with ${opt}"); [[ "$STATUS" == "pass" ]] && STATUS="warn"; }
    done
fi

# ---------- Removable / external media ----------
REMOVABLE_FS="vfat ntfs exfat iso9660 udf"
while IFS=' ' read -r device mountpoint fstype options _; do
    for rfs in $REMOVABLE_FS; do
        if [[ "$fstype" == "$rfs" ]]; then
            echo "[*] Removable mount: ${mountpoint} (${fstype})"
            if [[ "$REQUIRE_NOSUID_REMOVABLE" == "true" ]]; then
                echo "$options" | grep -qw nosuid \
                    && FINDINGS+=("PASS: ${mountpoint} (${fstype}) mounted with nosuid") \
                    || { FINDINGS+=("WARN: ${mountpoint} (${fstype}) not mounted with nosuid"); [[ "$STATUS" == "pass" ]] && STATUS="warn"; }
            fi
            echo "$options" | grep -qw noexec \
                || FINDINGS+=("WARN: ${mountpoint} (${fstype}) not mounted with noexec")
        fi
    done
done < /proc/mounts

# ---------- World-writable mount points ----------
if [[ "$CHECK_WORLD_WRITABLE_MOUNTS" == "true" ]]; then
    SKIP_FS="tmpfs devtmpfs sysfs proc devpts cgroup cgroup2 securityfs pstore efivarfs"
    while IFS=' ' read -r device mountpoint fstype _; do
        SKIP=false
        for sfs in $SKIP_FS; do [[ "$fstype" == "$sfs" ]] && SKIP=true && break; done
        $SKIP && continue

        if [[ -d "$mountpoint" ]]; then
            PERMS=$(stat -c "%a" "$mountpoint" 2>/dev/null) || continue
            OTHERS=$(( 8#$PERMS % 8 ))
            if (( (OTHERS & 2) != 0 )); then
                FINDINGS+=("WARN: Mount point ${mountpoint} is world-writable (${PERMS})")
                [[ "$STATUS" == "pass" ]] && STATUS="warn"
            fi
        fi
    done < /proc/mounts
fi

[[ "$STATUS" == "pass" ]] && FINDINGS+=("PASS: No critical filesystem security issues found")

echo ""
echo "=== Filesystem Security Check ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
