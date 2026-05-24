#!/usr/bin/env python3
import subprocess
import os
import re
from datetime import datetime, timezone


WEAK_SSH_CIPHERS = [
    "arcfour", "arcfour128", "arcfour256",
    "3des-cbc", "blowfish-cbc", "cast128-cbc",
    "aes128-cbc", "aes192-cbc", "aes256-cbc",
]
WEAK_SSH_MACS = [
    "hmac-md5", "hmac-md5-96", "hmac-sha1-96",
    "hmac-ripemd160", "umac-64@openssh.com",
]
WEAK_SSH_KEX = [
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "gss-gex-sha1-", "gss-group1-sha1-",
]

WEAK_TLS = ["TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"]


def _cmd(args, timeout=15):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return -1, "", f"nenájdený: {args[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def _check_crypto_policy(findings):
    policy_path = "/etc/crypto-policies/config"
    if not os.path.exists(policy_path):
        return

    try:
        with open(policy_path) as f:
            policy = f.read().strip()
        if policy in ("DEFAULT", "FUTURE", "FIPS"):
            findings.append(f"OK: Systémová crypto politika: {policy}")
        elif policy == "LEGACY":
            findings.append(
                "FAIL: Systémová crypto politika je LEGACY — povolené zastarané algoritmy vrátane SHA-1 a RC4"
            )
        else:
            findings.append(f"INFO: Systémová crypto politika: {policy} (neštandardná)")
    except (PermissionError, IOError) as e:
        findings.append(f"WARNING: Nepodarilo sa prečítať {policy_path}: {e}")


def _check_openssl_config(findings):
    openssl_configs = [
        "/etc/ssl/openssl.cnf",
        "/etc/pki/tls/openssl.cnf",
        "/usr/lib/ssl/openssl.cnf",
    ]

    config_found = False
    for path in openssl_configs:
        if not os.path.exists(path):
            continue
        config_found = True
        try:
            with open(path, errors="replace") as f:
                content = f.read()

            min_proto_match = re.search(r"MinProtocol\s*=\s*(\S+)", content)
            if min_proto_match:
                min_proto = min_proto_match.group(1)
                if min_proto in WEAK_TLS:
                    findings.append(
                        f"FAIL: {path} — MinProtocol={min_proto} je zastaraný, "
                        f"odporúčané minimum je TLSv1.2"
                    )
                else:
                    findings.append(f"OK: {path} — MinProtocol={min_proto}")
            else:
                findings.append(
                    f"WARNING: {path} — MinProtocol nie je explicitne nastavený "
                    f"(systém použije kompiláciou definované predvolené hodnoty)"
                )

            cipher_match = re.search(r"CipherString\s*=\s*(.+)", content)
            if cipher_match:
                cipher_str = cipher_match.group(1)
                for weak in ["RC4", "DES", "MD5", "NULL", "EXPORT", "aNULL", "eNULL"]:
                    if weak in cipher_str.upper():
                        findings.append(
                            f"FAIL: {path} — CipherString obsahuje slabý algoritmus: {weak}"
                        )

        except PermissionError:
            findings.append(f"WARNING: Nemám oprávnenie čítať {path}")

    if not config_found:
        findings.append("WARNING: OpenSSL konfiguračný súbor sa nenašiel")


def _check_ssh_crypto(findings):
    sshd_config = "/etc/ssh/sshd_config"
    if not os.path.exists(sshd_config):
        findings.append("INFO: sshd_config nenájdený — SSH crypto kontrola preskočená")
        return

    try:
        with open(sshd_config, errors="replace") as f:
            content = f.read().lower()
    except PermissionError:
        findings.append("WARNING: Nemám oprávnenie čítať sshd_config")
        return

    cipher_match = re.search(r"^ciphers\s+(.+)", content, re.MULTILINE)
    if cipher_match:
        ciphers = cipher_match.group(1)
        for weak in WEAK_SSH_CIPHERS:
            if weak in ciphers:
                findings.append(f"FAIL: sshd_config obsahuje slabú šifru: {weak}")
    else:
        findings.append("INFO: sshd_config neobsahuje explicitný zoznam Ciphers — použité sú predvolené")

    mac_match = re.search(r"^macs\s+(.+)", content, re.MULTILINE)
    if mac_match:
        macs = mac_match.group(1)
        for weak in WEAK_SSH_MACS:
            if weak in macs:
                findings.append(f"FAIL: sshd_config obsahuje slabý MAC algoritmus: {weak}")

    kex_match = re.search(r"^kexalgorithms\s+(.+)", content, re.MULTILINE)
    if kex_match:
        kex = kex_match.group(1)
        for weak in WEAK_SSH_KEX:
            if weak in kex:
                findings.append(f"FAIL: sshd_config obsahuje slabý KEX algoritmus: {weak}")


def _check_certificates(findings, warn_days):
    rc, _, _ = _cmd(["which", "openssl"])
    if rc != 0:
        findings.append("WARNING: openssl nie je dostupný — kontrola certifikátov preskočená")
        return

    certs_dir = "/etc/ssl/certs"
    if not os.path.isdir(certs_dir):
        findings.append(f"WARNING: Adresár {certs_dir} neexistuje")
        return

    now = datetime.now(tz=timezone.utc)
    checked = 0
    expired = []
    expiring_soon = []

    for fname in os.listdir(certs_dir):
        fpath = os.path.join(certs_dir, fname)
        if not (fname.endswith(".pem") or fname.endswith(".crt")):
            continue
        if os.path.islink(fpath):
            continue

        rc, out, _ = _cmd(
            ["openssl", "x509", "-enddate", "-noout", "-in", fpath],
            timeout=5
        )
        if rc != 0 or not out:
            continue

        match = re.search(r"notAfter=(.+)", out)
        if not match:
            continue

        try:
            exp_str = match.group(1).strip()
            exp_date = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
            exp_date = exp_date.replace(tzinfo=timezone.utc)
            checked += 1

            if exp_date < now:
                expired.append({"file": fname, "expired": exp_str})
                findings.append(f"CRITICAL: Certifikát {fname} už vypršal: {exp_str}")
            elif (exp_date - now).days <= warn_days:
                days_left = (exp_date - now).days
                expiring_soon.append({"file": fname, "expires": exp_str, "days_left": days_left})
                findings.append(
                    f"WARNING: Certifikát {fname} expiruje o {days_left} dní: {exp_str}"
                )
        except ValueError:
            continue

    if checked > 0:
        ok_count = checked - len(expired) - len(expiring_soon)
        findings.append(
            f"INFO: Skontrolovaných {checked} certifikátov — "
            f"{ok_count} OK, {len(expiring_soon)} expiruje čoskoro, {len(expired)} vypršaných"
        )
    else:
        findings.append(f"INFO: V {certs_dir} neboli nájdené žiadne .pem/.crt certifikáty na overenie")


def run(params=None):
    if params is None:
        params = {}

    cert_warn_days = params.get("cert_warn_days", 30)

    findings = []

    _check_crypto_policy(findings)
    _check_openssl_config(findings)
    _check_ssh_crypto(findings)
    _check_certificates(findings, cert_warn_days)

    critical = [f for f in findings if f.startswith("CRITICAL")]
    fails    = [f for f in findings if f.startswith("FAIL")]
    warnings = [f for f in findings if f.startswith("WARNING")]

    if critical:
        status = "CRITICAL"
        message = f"Vypršané certifikáty alebo kritické kryptografické problémy: {len(critical)} nálezov"
    elif fails:
        status = "FAIL"
        message = f"Slabé kryptografické algoritmy alebo zastaraná TLS konfigurácia: {len(fails)} nálezov"
    elif warnings:
        status = "WARNING"
        message = f"Kryptografická konfigurácia je čiastočne nedostatočná: {len(warnings)} upozornení"
    else:
        status = "OK"
        message = "Kryptografická konfigurácia spĺňa minimálne požiadavky NIS2"

    return {
        "test_name": "TLS and Crypto Configuration Check",
        "status": status,
        "message": message,
        "cert_warn_days": cert_warn_days,
        "findings": findings,
        "recommendation": (
            "Nastavte MinProtocol=TLSv1.2 alebo vyššie v openssl.cnf. "
            "Odstráňte slabé šifry (RC4, DES, 3DES) z SSH a systémovej konfigurácie. "
            "Obnovte certifikáty blízko expirácie. "
            "Na RHEL/Fedora systémoch použite príkaz 'update-crypto-policies --set DEFAULT' alebo 'FUTURE'."
        ) if status != "OK" else "Žiadna akcia nie je potrebná",
    }


if __name__ == "__main__":
    import json
    result = run({"cert_warn_days": 30})
    print(json.dumps(result, indent=2, ensure_ascii=False))
