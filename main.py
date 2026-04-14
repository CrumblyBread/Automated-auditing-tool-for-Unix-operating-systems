#!/usr/bin/env python3
import sys
import os
import json
import importlib.util
import subprocess
import argparse
from datetime import datetime


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
            print(f"Configuration loaded from {self.config_path}")
            return True
        except FileNotFoundError:
            print(f"Configuration file not found: {self.config_path}")
            return False
        except json.JSONDecodeError as e:
            print(f"Error parsing configuration file: {e}")
            return False

    def load_test_module(self, test_path):
        try:
            module_name = os.path.basename(test_path).replace('.py', '')
            spec = importlib.util.spec_from_file_location(module_name, test_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        except Exception as e:
            print(f"Error loading test module {test_path}: {e}")
            return None

    def discover_tests(self):
        if 'tests' not in self.config:
            print("No tests defined in configuration")
            return False

        tests_dir = self.config.get('tests_directory', 'tests')

        for test_config in self.config['tests']:
            if not test_config.get('enabled', False):
                print(f"Skipping disabled test: {test_config['name']}")
                continue

            test_file = test_config['file']
            test_path = os.path.join(tests_dir, test_file)

            if not os.path.exists(test_path):
                print(f"Test file not found: {test_path}")
                continue

            module = self.load_test_module(test_path)
            if module and hasattr(module, 'run'):
                self.tests[test_config['name']] = {
                    'module': module,
                    'config': test_config
                }
                print(f"Loaded test: {test_config['name']}")
            else:
                print(f"Test module {test_file} missing 'run' function")

        return len(self.tests) > 0

    def run_test(self, test_name, test_info):
        print(f"\n{'='*50}")
        print(f"Running: {test_name}")
        print(f"{'='*50}")

        try:
            module = test_info['module']
            config = test_info['config']
            params = config.get('parameters', {})
            result = module.run(params)

            self.results[test_name] = {
                'status': 'success',
                'result': result,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            print(f"Error executing test {test_name}: {e}")
            self.results[test_name] = {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def run_all_tests(self):
        if not self.tests:
            print("No tests loaded to execute")
            return

        print(f"\nStarting enumeration with {len(self.tests)} test(s)")

        for test_name, test_info in self.tests.items():
            self.run_test(test_name, test_info)

        self.print_summary()

    def print_summary(self):
        print(f"\n{'='*60}")
        print("ENUMERATION SUMMARY")
        print(f"{'='*60}")

        successful = sum(1 for r in self.results.values() if r['status'] == 'success')
        failed = sum(1 for r in self.results.values() if r['status'] == 'error')

        print(f"Total tests run: {len(self.results)}")
        print(f"Successful: {successful}")
        print(f"Failed: {failed}")

        if self.config.get('save_results', False):
            self.save_results()

    def save_results(self):
        output_file = self.config.get('output_file', 'enumeration_results.json')
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"\nResults saved to: {output_file}")
        except Exception as e:
            print(f"Error saving results: {e}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Enumeration / security audit framework",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "config",
        nargs="?",
        default="config.json",
        help="Cesta ku konfiguračnému súboru (default: config.json)",
    )

    remote_group = parser.add_argument_group("Remote mode (SSH)")
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

    print("Start\n")

    framework = EnumerationFramework(args.config)

    if not framework.load_config():
        sys.exit(1)

    if not framework.discover_tests():
        print("No tests loaded. Exiting.")
        sys.exit(1)

    framework.run_all_tests()

    print("\nEnumeration complete!")


if __name__ == "__main__":
    main()