#!/usr/bin/env python3
import subprocess
import re


def run(params):
    print("Spúšťam test verzie jadra...")
    
    min_kernel_version = params.get('min_kernel_version', '5.4.0')
    
    try:
        result = subprocess.run(
            ['uname', '-r'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode != 0:
            return {
                'status': 'ERROR',
                'message': 'Nepodarilo sa získať verziu jadra',
                'error': result.stderr.strip()
            }
        
        kernel_version = result.stdout.strip()
        print(f"[+] Aktuálna verzia jadra: {kernel_version}")
        
        version_match = re.match(r'(\d+)\.(\d+)\.(\d+)', kernel_version)
        if not version_match:
            return {
                'status': 'ERROR',
                'message': 'Nepodarilo sa extrahovať verziu jadra',
                'kernel_version': kernel_version
            }
        
        current_version_parts = [int(x) for x in version_match.groups()]
        
        min_version_match = re.match(r'(\d+)\.(\d+)\.(\d+)', min_kernel_version)
        if not min_version_match:
            return {
                'status': 'ERROR',
                'message': 'Neplatný formát minimálnej verzie jadra',
                'min_kernel_version': min_kernel_version
            }
        
        min_version_parts = [int(x) for x in min_version_match.groups()]
        
        is_outdated = compare_versions(current_version_parts, min_version_parts) < 0
        
        if is_outdated:
            return {
                'status': 'WARNING',
                'message': 'Systém používa zastaranú verziu jadra',
                'kernel_version': kernel_version,
                'min_recommended_version': min_kernel_version,
                'recommendation': f'Odporúča sa aktualizácia jadra na verziu {min_kernel_version} alebo novšiu',
                'risk': 'Potenciálne bezpečnostné riziko - zastaraný komponent systému',
                'severity': 'MEDIUM'
            }
        else:
            return {
                'status': 'OK',
                'message': 'Verzia jadra je aktuálna',
                'kernel_version': kernel_version,
                'min_recommended_version': min_kernel_version
            }
            
    except subprocess.TimeoutExpired:
        return {
            'status': 'ERROR',
            'message': 'Timeout pri vykonávaní príkazu uname',
            'error': 'Príkaz trval príliš dlho'
        }
    except FileNotFoundError:
        return {
            'status': 'ERROR',
            'message': 'Príkaz uname nebol nájdený',
            'error': 'System neobsahuje príkaz uname'
        }
    except Exception as e:
        return {
            'status': 'ERROR',
            'message': 'Neočakávaná chyba pri teste verzie jadra',
            'error': str(e)
        }


def compare_versions(version1, version2):
    for v1, v2 in zip(version1, version2):
        if v1 < v2:
            return -1
        elif v1 > v2:
            return 1
    return 0


if __name__ == "__main__":
    test_params = {
        'min_kernel_version': '5.4.0'
    }
    result = run(test_params)
    print(f"\nVýsledok testu:")
    for key, value in result.items():
        print(f"  {key}: {value}")