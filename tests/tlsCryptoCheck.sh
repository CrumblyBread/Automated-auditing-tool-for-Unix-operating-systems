#!/usr/bin/env bash

set -euo pipefail

CERT_WARN_DAYS="${CERT_WARN_DAYS:-30}"

WEAK_TLS="TLSv1 TLSv1.0 TLSv1.1 SSLv2 SSLv3"
WEAK_SSH_CIPHERS="arcfour arcfour128 arcfour256 3des-cbc blowfish-cbc cast128-cbc aes128-cbc aes192-cbc aes256-cbc"
WEAK_SSH_MACS="hmac-md5 hmac-md5-96 hmac-sha1-96 hmac-ripemd160"
WEAK_SSH_KEX="diffie-hellman-group1-sha1 diffie-hellman-group14-sha1"

json_escape() {
    printf '%s' "$1" \
        | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/g' \
        | tr -d '\n' \
        | sed 's/\\n$//'
}

FINDINGS=""
CRITICAL_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

add_finding() {
    local msg="$1"
    if [ -z "$FINDINGS" ]; then
        FINDINGS="\"$(json_escape "$msg")\""
    else
        FINDINGS="${FINDINGS}, \"$(json_escape "$msg")\""
    fi
    case "$msg" in
        CRITICAL*) CRITICAL_COUNT=$((CRITICAL_COUNT + 1)) ;;
        FAIL*)     FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        WARNING*)  WARN_COUNT=$((WARN_COUNT + 1)) ;;
    esac
}

check_crypto_policy() {
    local policy_path="/etc/crypto-policies/config"
    [ ! -f "$policy_path" ] && return

    local policy
    policy=$(cat "$policy_path" 2>/dev/null | tr -d '[:space:]')

    case "$policy" in
        DEFAULT|FUTURE|FIPS)
            add_finding "OK: Systémová crypto politika: ${policy}"
            ;;
        LEGACY)
            add_finding "FAIL: Systémová crypto politika je LEGACY — povolené zastarané algoritmy (SHA-1, RC4)"
            ;;
        *)
            add_finding "INFO: Systémová crypto politika: ${policy} (neštandardná)"
            ;;
    esac
}

check_openssl_config() {
    local openssl_configs=(
        "/etc/ssl/openssl.cnf"
        "/etc/pki/tls/openssl.cnf"
        "/usr/lib/ssl/openssl.cnf"
    )

    local config_found=0
    for cfg_path in "${openssl_configs[@]}"; do
        [ ! -f "$cfg_path" ] && continue
        config_found=1

        local min_proto
        min_proto=$(grep -E '^[[:space:]]*MinProtocol[[:space:]]*=' "$cfg_path" \
                    2>/dev/null | head -1 | sed 's/.*=[[:space:]]*//' | tr -d '[:space:]')

        if [ -n "$min_proto" ]; then
            local is_weak=0
            for weak in $WEAK_TLS; do
                [ "$min_proto" = "$weak" ] && is_weak=1 && break
            done
            if [ "$is_weak" -eq 1 ]; then
                add_finding "FAIL: ${cfg_path} — MinProtocol=${min_proto} je zastaraný (odporúčané: TLSv1.2+)"
            else
                add_finding "OK: ${cfg_path} — MinProtocol=${min_proto}"
            fi
        else
            add_finding "WARNING: ${cfg_path} — MinProtocol nie je explicitne nastavený"
        fi

        local cipher_str
        cipher_str=$(grep -E '^[[:space:]]*CipherString[[:space:]]*=' "$cfg_path" \
                     2>/dev/null | head -1 | sed 's/.*=[[:space:]]*//' | tr '[:lower:]' '[:upper:]')
        if [ -n "$cipher_str" ]; then
            for weak in RC4 DES MD5 NULL EXPORT aNULL eNULL; do
                if echo "$cipher_str" | grep -q "$weak"; then
                    add_finding "FAIL: ${cfg_path} — CipherString obsahuje slabý algoritmus: ${weak}"
                fi
            done
        fi
    done

    if [ "$config_found" -eq 0 ]; then
        add_finding "WARNING: OpenSSL konfiguračný súbor sa nenašiel"
    fi
}

check_ssh_crypto() {
    local sshd_config="/etc/ssh/sshd_config"

    if [ ! -f "$sshd_config" ]; then
        add_finding "INFO: sshd_config nenájdený — SSH crypto kontrola preskočená"
        return
    fi

    local content
    content=$(cat "$sshd_config" 2>/dev/null | tr '[:upper:]' '[:lower:]')

    local ciphers_line
    ciphers_line=$(echo "$content" | grep -E '^[[:space:]]*ciphers[[:space:]]' | head -1)
    if [ -n "$ciphers_line" ]; then
        for weak in $WEAK_SSH_CIPHERS; do
            if echo "$ciphers_line" | grep -q "$weak"; then
                add_finding "FAIL: sshd_config obsahuje slabú šifru: ${weak}"
            fi
        done
    else
        add_finding "INFO: sshd_config neobsahuje explicitný zoznam Ciphers — použité sú predvolené hodnoty OpenSSH"
    fi

    local macs_line
    macs_line=$(echo "$content" | grep -E '^[[:space:]]*macs[[:space:]]' | head -1)
    if [ -n "$macs_line" ]; then
        for weak in $WEAK_SSH_MACS; do
            if echo "$macs_line" | grep -q "$weak"; then
                add_finding "FAIL: sshd_config obsahuje slabý MAC algoritmus: ${weak}"
            fi
        done
    fi

    local kex_line
    kex_line=$(echo "$content" | grep -E '^[[:space:]]*kexalgorithms[[:space:]]' | head -1)
    if [ -n "$kex_line" ]; then
        for weak in $WEAK_SSH_KEX; do
            if echo "$kex_line" | grep -q "$weak"; then
                add_finding "FAIL: sshd_config obsahuje slabý KEX algoritmus: ${weak}"
            fi
        done
    fi
}

check_certificates() {
    if ! command -v openssl &>/dev/null; then
        add_finding "WARNING: openssl nie je dostupný — kontrola certifikátov preskočená"
        return
    fi

    local certs_dir="/etc/ssl/certs"
    if [ ! -d "$certs_dir" ]; then
        add_finding "WARNING: Adresár ${certs_dir} neexistuje"
        return
    fi

    local now_ts
    now_ts=$(date +%s)
    local warn_ts=$(( now_ts + CERT_WARN_DAYS * 86400 ))

    local checked=0 expired=0 expiring=0 ok_count=0

    while IFS= read -r cert_file; do
        [ -L "$cert_file" ] && continue
        [ ! -f "$cert_file" ] && continue

        local end_date
        end_date=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null \
                   | sed 's/notAfter=//')
        [ -z "$end_date" ] && continue

        local exp_ts
        exp_ts=$(date -d "$end_date" +%s 2>/dev/null) || continue

        checked=$((checked + 1))
        local fname
        fname=$(basename "$cert_file")

        if [ "$exp_ts" -lt "$now_ts" ]; then
            expired=$((expired + 1))
            add_finding "CRITICAL: Certifikát ${fname} už vypršal: ${end_date}"
        elif [ "$exp_ts" -lt "$warn_ts" ]; then
            expiring=$((expiring + 1))
            local days_left=$(( (exp_ts - now_ts) / 86400 ))
            add_finding "WARNING: Certifikát ${fname} expiruje o ${days_left} dní: ${end_date}"
        else
            ok_count=$((ok_count + 1))
        fi
    done < <(find "$certs_dir" -maxdepth 1 \( -name "*.pem" -o -name "*.crt" \) 2>/dev/null)

    if [ "$checked" -gt 0 ]; then
        add_finding "INFO: Skontrolovaných ${checked} certifikátov — ${ok_count} OK, ${expiring} expiruje čoskoro, ${expired} vypršaných"
    else
        add_finding "INFO: V ${certs_dir} neboli nájdené žiadne .pem/.crt certifikáty"
    fi
}

main() {
    check_crypto_policy
    check_openssl_config
    check_ssh_crypto
    check_certificates

    local status message recommendation

    if [ "$CRITICAL_COUNT" -gt 0 ]; then
        status="CRITICAL"
        message="Vypršané certifikáty alebo kritické kryptografické problémy: ${CRITICAL_COUNT} nálezov"
        recommendation="Okamžite obnovte vypršané certifikáty. Skontrolujte a opravte kryptografickú konfiguráciu."
    elif [ "$FAIL_COUNT" -gt 0 ]; then
        status="FAIL"
        message="Slabé kryptografické algoritmy alebo zastaraná TLS konfigurácia: ${FAIL_COUNT} nálezov"
        recommendation="Nastavte MinProtocol=TLSv1.2 v openssl.cnf. Odstráňte slabé šifry z SSH konfigurácie. Na RHEL/Fedora: 'update-crypto-policies --set DEFAULT'."
    elif [ "$WARN_COUNT" -gt 0 ]; then
        status="WARNING"
        message="Kryptografická konfigurácia je čiastočne nedostatočná: ${WARN_COUNT} upozornení"
        recommendation="Explicitne nastavte MinProtocol a CipherString v openssl.cnf. Obnovte certifikáty blízko expirácie."
    else
        status="OK"
        message="Kryptografická konfigurácia spĺňa minimálne požiadavky NIS2"
        recommendation="Žiadna akcia nie je potrebná"
    fi

    cat <<EOF
{
  "test_name": "TLS and Crypto Configuration Check",
  "status": "${status}",
  "message": "$(json_escape "$message")",
  "cert_warn_days": ${CERT_WARN_DAYS},
  "findings": [${FINDINGS}],
  "recommendation": "$(json_escape "$recommendation")"
}
EOF

    case "$status" in
        "OK")                exit 0 ;;
        "WARNING")           exit 1 ;;
        "FAIL"|"CRITICAL"|*) exit 2 ;;
    esac
}

main "$@"
