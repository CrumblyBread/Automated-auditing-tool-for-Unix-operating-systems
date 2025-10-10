#!/usr/bin/env python3
import sys
import os
import json
import importlib.util
from datetime import datetime


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
            print(f"[+] Configuration loaded from {self.config_path}")
            return True
        except FileNotFoundError:
            print(f"[!] Configuration file not found: {self.config_path}")
            return False
        except json.JSONDecodeError as e:
            print(f"[!] Error parsing configuration file: {e}")
            return False
    
    def load_test_module(self, test_path):
        try:
            module_name = os.path.basename(test_path).replace('.py', '')
            spec = importlib.util.spec_from_file_location(module_name, test_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        except Exception as e:
            print(f"[!] Error loading test module {test_path}: {e}")
            return None
    
    def discover_tests(self):
        if 'tests' not in self.config:
            print("[!] No tests defined in configuration")
            return False
        
        tests_dir = self.config.get('tests_directory', 'tests')
        
        for test_config in self.config['tests']:
            if not test_config.get('enabled', False):
                print(f"[-] Skipping disabled test: {test_config['name']}")
                continue
            
            test_file = test_config['file']
            test_path = os.path.join(tests_dir, test_file)
            
            if not os.path.exists(test_path):
                print(f"[!] Test file not found: {test_path}")
                continue
            
            module = self.load_test_module(test_path)
            if module and hasattr(module, 'run'):
                self.tests[test_config['name']] = {
                    'module': module,
                    'config': test_config
                }
                print(f"[+] Loaded test: {test_config['name']}")
            else:
                print(f"[!] Test module {test_file} missing 'run' function")
        
        return len(self.tests) > 0
    
    def run_test(self, test_name, test_info):
        print(f"\n{'='*60}")
        print(f"Running: {test_name}")
        print(f"{'='*60}")
        
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
            print(f"[!] Error executing test {test_name}: {e}")
            self.results[test_name] = {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def run_all_tests(self):
        if not self.tests:
            print("[!] No tests loaded to execute")
            return
        
        print(f"\n[+] Starting enumeration with {len(self.tests)} test(s)")
        
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


def main():
    print("Start")
    
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.json"
    
    framework = EnumerationFramework(config_path)
    
    if not framework.load_config():
        sys.exit(1)
    
    if not framework.discover_tests():
        print("No tests loaded. Exiting.")
        sys.exit(1)
    
    framework.run_all_tests()
    
    print("\nEnumeration complete!")


if __name__ == "__main__":
    main()