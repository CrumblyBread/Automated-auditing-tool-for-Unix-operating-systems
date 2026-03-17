#!/usr/bin/env bash
# ============================================================
# packagesCheck.sh — Installed Packages Check
# Params (env vars):
#   CHECK_KNOWN_VULNERABLE   (default: true)
#   VULNERABLE_PACKAGES      (default: known dangerous list — space-separated)
#   CHECK_DEV_TOOLS          (default: true)
# ============================================================

CHECK_KNOWN_VULNERABLE="${CHECK_KNOWN_VULNERABLE:-true}"
CHECK_DEV_TOOLS="${CHECK_DEV_TOOLS:-true}"
VULNERABLE_PACKAGES="${VULNERABLE_PACKAGES:-telnet rsh-client rsh-server talk ntalk \
xinetd inetd nis yp-tools tftp atftpd tftpd tftpd-hpa rpcbind}"

STATUS="pass"
FINDINGS=()
PKG_MGR=""
INSTALLED_NAMES=()

# ---------- detect package manager and collect installed packages ----------
if command -v dpkg-query &>/dev/null; then
    PKG_MGR="dpkg"
    while IFS=$'\t' read -r pkg _; do
        INSTALLED_NAMES+=("$pkg")
    done < <(dpkg-query -W -f='${Package}\t${Status}\n' 2>/dev/null \
              | awk -F'\t' '$2 ~ /install ok installed/ {print $1"\t"}')
    FINDINGS+=("INFO: ${#INSTALLED_NAMES[@]} packages installed (dpkg)")

elif command -v rpm &>/dev/null; then
    PKG_MGR="rpm"
    while IFS= read -r pkg; do
        INSTALLED_NAMES+=("$pkg")
    done < <(rpm -qa --queryformat '%{NAME}\n' 2>/dev/null)
    FINDINGS+=("INFO: ${#INSTALLED_NAMES[@]} packages installed (rpm)")

elif command -v apk &>/dev/null; then
    PKG_MGR="apk"
    while IFS= read -r pkg; do
        # apk info output: name-version, strip version
        INSTALLED_NAMES+=("${pkg%-*}")
    done < <(apk info 2>/dev/null)
    FINDINGS+=("INFO: ${#INSTALLED_NAMES[@]} packages installed (apk)")

else
    FINDINGS+=("WARN: No supported package manager found (dpkg/rpm/apk)")
    STATUS="warn"
    echo "=== Installed Packages Check ==="
    echo "Status: ${STATUS}"
    echo "  ${FINDINGS[0]}"
    exit 0
fi

echo "[*] Checking ${#INSTALLED_NAMES[@]} installed packages via ${PKG_MGR}"

# Build a lookup set
declare -A PKG_SET
for pkg in "${INSTALLED_NAMES[@]}"; do PKG_SET[$pkg]=1; done

# ---------- known dangerous / legacy packages ----------
if [[ "$CHECK_KNOWN_VULNERABLE" == "true" ]]; then
    ANY_FOUND=false
    for bad in $VULNERABLE_PACKAGES; do
        if [[ "${PKG_SET[$bad]+_}" ]]; then
            FINDINGS+=("WARN: Dangerous/legacy package installed: ${bad}")
            [[ "$STATUS" == "pass" ]] && STATUS="warn"
            ANY_FOUND=true
        fi
    done
    [[ "$ANY_FOUND" == "false" ]] && FINDINGS+=("PASS: No known dangerous packages found")
fi

# ---------- development tools on production ----------
if [[ "$CHECK_DEV_TOOLS" == "true" ]]; then
    DEV_TOOLS="gcc g++ make gdb strace ltrace build-essential binutils nasm"
    FOUND_DEV=()
    for tool in $DEV_TOOLS; do
        [[ "${PKG_SET[$tool]+_}" ]] && FOUND_DEV+=("$tool")
    done
    if (( ${#FOUND_DEV[@]} > 0 )); then
        FINDINGS+=("INFO: Development tools installed (review if this is production): ${FOUND_DEV[*]}")
    else
        FINDINGS+=("PASS: No development/compiler tools found")
    fi
fi

# ---------- network sniffing / hacking tools ----------
NETWORK_TOOLS="nmap masscan wireshark tcpdump netcat ncat hydra john aircrack-ng sqlmap metasploit-framework"
FOUND_NET=()
for tool in $NETWORK_TOOLS; do
    [[ "${PKG_SET[$tool]+_}" ]] && FOUND_NET+=("$tool")
done
if (( ${#FOUND_NET[@]} > 0 )); then
    FINDINGS+=("WARN: Network/security tools installed (verify intent): ${FOUND_NET[*]}")
    [[ "$STATUS" == "pass" ]] && STATUS="warn"
fi

# ---------- debsecan (apt/dpkg systems only) ----------
if [[ "$PKG_MGR" == "dpkg" ]] && command -v debsecan &>/dev/null; then
    echo "[*] Running debsecan (may take a moment)..."
    VULN_COUNT=$(debsecan --only-fixed 2>/dev/null | wc -l)
    if (( VULN_COUNT > 0 )); then
        FINDINGS+=("FAIL: ${VULN_COUNT} unpatched CVE(s) found via debsecan")
        STATUS="fail"
        debsecan --only-fixed 2>/dev/null | head -10 | while IFS= read -r line; do
            FINDINGS+=("  ${line}")
        done
    else
        FINDINGS+=("PASS: No unpatched CVEs found via debsecan")
    fi
else
    FINDINGS+=("INFO: debsecan not available — install for CVE scanning (apt install debsecan)")
fi

echo ""
echo "=== Installed Packages Check ==="
echo "Status: ${STATUS}"
for f in "${FINDINGS[@]}"; do echo "  ${f}"; done
