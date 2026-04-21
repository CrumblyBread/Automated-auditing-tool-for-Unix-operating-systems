#!/usr/bin/env python3
import sys
import os
import json
import importlib.util
import subprocess
import argparse
from datetime import datetime


def _normalize_severity_value(value) -> str | None:
    """
    Normalizuje severitu na povolené hodnoty:
    None, Low, Medium, High, Critical
    """
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None

    upper = s.upper()
    mapping = {
        "NONE": None,
        "INFO": None,
        "INFORMATION": None,
        "LOW": "Low",
        "MEDIUM": "Medium",
        "MODERATE": "Medium",
        "HIGH": "High",
        "SEVERE": "High",
        "CRITICAL": "Critical",
    }
    if upper in mapping:
        return mapping[upper]

    # Ak už niekto použil správny tvar (napr. "Low"), zachovaj.
    allowed = {None, "Low", "Medium", "High", "Critical"}
    if s in allowed:
        return s

    return None


def _severity_from_status(status) -> str | None:
    if status is None:
        return None
    s = str(status).strip().lower()
    if not s:
        return None

    if "critical" in s:
        return "Critical"
    if "error" in s:
        return "High"
    if "fail" in s:
        return "High"
    if "warn" in s:
        return "Medium"
    if s in {"pass", "ok", "success", "completed"}:
        return None

    return None


def _ensure_test_severity(result):
    """
    Zabezpečí, že výsledok testu (dict) bude obsahovať kľúč `severity`
    s hodnotou: None/Low/Medium/High/Critical.
    """
    if not isinstance(result, dict):
        return result

    # Vždy prepíš severitu do novej škály (aj keď test už severity obsahuje)
    result["severity"] = _severity_from_status(result.get("status"))
    return result


def _score_penalty_from_severity(severity) -> int:
    sev = _normalize_severity_value(severity)
    penalties = {
        None: 0,
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4,
    }
    return penalties.get(sev, 0)


def _compute_score(results: dict) -> tuple[int, int, int]:
    """
    Vráti (score, max_score, n_tests).
    Do n_tests počítame len položky, ktoré vyzerajú ako výsledok testu.
    """
    if not isinstance(results, dict):
        return (0, 0, 0)

    test_items = []
    for k, v in results.items():
        if k == "__summary__":
            continue
        if isinstance(v, dict) and v.get("status") in {"success", "error"}:
            test_items.append(v)

    n = len(test_items)
    max_score = n * 4
    total_penalty = 0
    for r in test_items:
        # Preferuj severity z výsledku testu; fallback na wrapper severity
        sev = None
        if isinstance(r.get('result'), dict):
            sev = r['result'].get('severity')
        if sev is None and 'severity' in r:
            sev = r.get('severity')
        total_penalty += _score_penalty_from_severity(sev)

    score = max(0, max_score - total_penalty)
    return (score, max_score, n)


def _make_ssh_wrapper(host: str, ssh_user: str | None, ssh_key: str | None):
    _original_run = subprocess.run

    def ssh_run(cmd, *args, **kwargs):
        if isinstance(cmd, list):
            remote_cmd = " ".join(_shell_quote(c) for c in cmd)
        else:
            remote_cmd = cmd

        ssh_cmd = _build_ssh_cmd(host, remote_cmd, ssh_user, ssh_key)
        print(f"  [SSH→{host}] {remote_cmd}")
        return _original_run(ssh_cmd, *args, **kwargs)

    return ssh_run


def _shell_quote(s: str) -> str:
    import shlex
    return shlex.quote(s)


def _build_ssh_cmd(host: str, remote_cmd: str,
                   user: str | None, key: str | None) -> list:
    target = f"{user}@{host}" if user else host
    base = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",          
        "-o", "ConnectTimeout=10",
    ]
    if key:
        base += ["-i", key]
    base += [target, remote_cmd]
    return base


def patch_subprocess_for_remote(host: str,
                                 ssh_user: str | None = None,
                                 ssh_key: str | None = None):

    subprocess.run = _make_ssh_wrapper(host, ssh_user, ssh_key)
    print(f"[Remote mode] subprocess.run presmerovaný na {host}")


def verify_ssh_connectivity(host: str,
                             ssh_user: str | None = None,
                             ssh_key: str | None = None) -> bool:
    target = f"{ssh_user}@{host}" if ssh_user else host
    cmd = ["ssh",
           "-o", "StrictHostKeyChecking=no",
           "-o", "BatchMode=yes",
           "-o", "ConnectTimeout=10"]
    if ssh_key:
        cmd += ["-i", ssh_key]
    cmd += [target, "echo OK"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0 and "OK" in result.stdout:
            print(f"[Remote mode] SSH spojenie s {host} overené ✓")
            return True
        else:
            print(f"[Remote mode] SSH spojenie zlyhalo: {result.stderr.strip()}")
            return False
    except subprocess.TimeoutExpired:
        print("[Remote mode] SSH timeout pri overovaní spojenia")
        return False
    except Exception as e:
        print(f"[Remote mode] Chyba pri overovaní SSH: {e}")
        return False
    
class EnumerationFramework:
    def __init__(self, config_path="config.json"):
        self.config_path = config_path
        self.config = {}
        self.tests = {}
        self.results = {}

    def load_config(self):
        try:
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)
            print(f"Konfigurácia načítaná zo súboru: {self.config_path}")
            return True
        except FileNotFoundError:
            print(f"Konfiguračný súbor sa nenašiel: {self.config_path}")
            return False
        except json.JSONDecodeError as e:
            print(f"Error pri parsovaní konfiguračného súboru: {e}")
            return False

    def load_test_module(self, test_path):
        try:
            module_name = os.path.basename(test_path).replace('.py', '')
            spec = importlib.util.spec_from_file_location(module_name, test_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        except Exception as e:
            print(f"Error pri načítaní test modulu {test_path}: {e}")
            return None

    def discover_tests(self):
        if 'tests' not in self.config:
            print("V konfigurácii nie sú definované žiadne testy")
            return False

        tests_dir = self.config.get('tests_directory', 'tests')

        for test_config in self.config['tests']:
            if not test_config.get('enabled', False):
                print(f"Preskakujem deaktivovaný test: {test_config['name']}")
                continue

            test_file = test_config['file']
            test_path = os.path.join(tests_dir, test_file)

            if not os.path.exists(test_path):
                print(f"Súbor testu sa nenašiel: {test_path}")
                continue

            module = self.load_test_module(test_path)
            if module and hasattr(module, 'run'):
                self.tests[test_config['name']] = {
                    'module': module,
                    'config': test_config
                }
                print(f"Načítaný test: {test_config['name']}")
            else:
                print(f"Test modul {test_file} neobsahuje funkciu 'run'")

        return len(self.tests) > 0

    def run_test(self, test_name, test_info):
        print(f"\n{'='*50}")
        print(f"Spúšťam: {test_name}")
        print(f"{'='*50}")

        try:
            module = test_info['module']
            config = test_info['config']
            params = config.get('parameters', {})
            result = module.run(params)
            result = _ensure_test_severity(result)

            self.results[test_name] = {
                'status': 'success',
                'result': result,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            print(f"Error pri vykonávaní testu {test_name}: {e}")
            self.results[test_name] = {
                'status': 'error',
                'error': str(e),
                'severity': 'High',
                'timestamp': datetime.now().isoformat()
            }

    def run_all_tests(self):
        if not self.tests:
            print("Nie sú načítané žiadne testy na spustenie")
            return

        print(f"\nSpúšťam audit s {len(self.tests)} test(ami)")

        for test_name, test_info in self.tests.items():
            self.run_test(test_name, test_info)

        self.print_summary()

    def print_summary(self):
        print(f"\n{'='*60}")
        print("SÚHRN AUDITU")
        print(f"{'='*60}")

        successful = sum(1 for r in self.results.values() if r['status'] == 'success')
        failed = sum(1 for r in self.results.values() if r['status'] == 'error')

        print(f"Celkovo spustených testov: {len(self.results)}")
        print(f"Úspešné: {successful}")
        print(f"Neúspešné: {failed}")

        # Bodové hodnotenie
        score, max_score, n = _compute_score(self.results)

        print(f"\nBodové hodnotenie: {score}/{max_score}")

        if self.config.get('save_results', False):
            self.save_results()

    def save_results(self):
        output_file = self.config.get('output_file', 'enumeration_results.json')
        try:
            score, max_score, n = _compute_score(self.results)
            payload = dict(self.results)
            payload["__summary__"] = {
                "tests_count": n,
                "score": score,
                "max_score": max_score,
                "scoring": {
                    "start": "n*4",
                    "penalties": {
                        "Critical": 4,
                        "High": 3,
                        "Medium": 2,
                        "Low": 1,
                        "None": 0,
                    },
                },
            }
            with open(output_file, 'w') as f:
                json.dump(payload, f, indent=2)
            print(f"\nVýsledky uložené do: {output_file}")
        except Exception as e:
            print(f"Error pri ukladaní výsledkov: {e}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Rámec pre enumeráciu / bezpečnostný audit",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "config",
        nargs="?",
        default="config.json",
        help="Cesta ku konfiguračnému súboru (default: config.json)",
    )

    remote_group = parser.add_argument_group("Vzdialený režim (SSH)")
    remote_group.add_argument(
        "--remote",
        metavar="HOST",
        help=(
            "IP adresa alebo hostname vzdialeného stroja.\n"
            "Každý subprocess.run v testoch sa automaticky presmeruje cez SSH.\n"
            "Príklad: --remote 192.168.1.10"
        ),
    )
    remote_group.add_argument(
        "--ssh-user",
        metavar="USER",
        help="SSH užívateľ (default: aktuálny lokálny užívateľ)",
    )
    remote_group.add_argument(
        "--ssh-key",
        metavar="PATH",
        help="Cesta k SSH private key (default: ~/.ssh/id_rsa)",
    )
    remote_group.add_argument(
        "--no-verify",
        action="store_true",
        help="Preskočiť overenie SSH spojenia pred spustením testov",
    )

    return parser.parse_args()

def main():
    args = parse_args()

    if args.remote:
        print(f"\n[Remote mode] Cieľový host: {args.remote}")

        if not args.no_verify:
            if not verify_ssh_connectivity(args.remote, args.ssh_user, args.ssh_key):
                print("Nepodarilo sa overiť SSH spojenie. Použite --no-verify na preskočenie.")
                sys.exit(1)

        patch_subprocess_for_remote(args.remote, args.ssh_user, args.ssh_key)
    else:
        print("[Local mode] Testy sa spustia lokálne")

    print("Štart\n")

    framework = EnumerationFramework(args.config)

    if not framework.load_config():
        sys.exit(1)

    if not framework.discover_tests():
        print("Nenačítali sa žiadne testy. Končím.")
        sys.exit(1)

    framework.run_all_tests()

    print("\nAudit dokončený!")


if __name__ == "__main__":
    main()