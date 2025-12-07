#!/usr/bin/env python3
import subprocess
import re


def run(params):
    print("Spúšťam test dostupných aktualizácií...")
    
    max_updates_warning = params.get('max_updates_warning', 10)
    max_updates_critical = params.get('max_updates_critical', 50)
    check_security_only = params.get('check_security_only', False)
    
    try:
        print("Aktualizujem zoznam balíkov...")
        update_result = subprocess.run(
            ['sudo', 'apt', 'update'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if update_result.returncode != 0:
            print(f"Varovanie pri apt update: {update_result.stderr}")
        
        result = subprocess.run(
            ['apt', 'list', '--upgradable'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            return {
                'status': 'ERROR',
                'message': 'Nepodarilo sa získať zoznam aktualizácií',
                'error': result.stderr.strip()
            }
        
        output = result.stdout.strip()
        
        upgradable_packages = parse_upgradable_packages(output)
        
        security_updates = []
        if check_security_only:
            security_updates = check_security_updates()
        
        total_updates = len(upgradable_packages)
        
        print(f"Nájdených {total_updates} aktualizovateľných balíkov")
        
        if total_updates == 0:
            return {
                'status': 'PASS',
                'message': 'Systém je aktuálny, žiadne dostupné aktualizácie',
                'upgradable_packages_count': 0,
                'severity': 'INFO'
            }
        
        if total_updates >= max_updates_critical:
            status = 'CRITICAL'
            severity = 'CRITICAL'
            message = f'Kritický počet dostupných aktualizácií: {total_updates} balíkov'
        elif total_updates >= max_updates_warning:
            status = 'WARNING'
            severity = 'HIGH'
            message = f'Vysoký počet dostupných aktualizácií: {total_updates} balíkov'
        else:
            status = 'WARNING'
            severity = 'MEDIUM'
            message = f'Dostupné aktualizácie: {total_updates} balíkov'
        
        result_data = {
            'status': status,
            'message': message,
            'upgradable_packages_count': total_updates,
            'upgradable_packages': upgradable_packages[:20],  # Prvých 20 pre prehľadnosť
            'severity': severity,
            'security_risk': 'Zastarané komponenty môžu obsahovať známe bezpečnostné zraniteľnosti',
            'recommendation': 'Aktualizujte systém na najnovšie verzie balíkov',
            'commands': [
                'sudo apt update',
                'sudo apt upgrade',
                'sudo apt dist-upgrade'
            ],
            'impact': 'Zastarané komponenty sú jednou z najkritickejších oblastí správy serverov'
        }
        
        if total_updates > 20:
            result_data['note'] = f'Zobrazených prvých 20 z {total_updates} balíkov'
            result_data['full_list_available'] = True
        
        if check_security_only and security_updates:
            result_data['security_updates_count'] = len(security_updates)
            result_data['security_updates'] = security_updates[:10]
            if len(security_updates) > 0:
                result_data['severity'] = 'CRITICAL'
                result_data['message'] = f'Dostupné bezpečnostné aktualizácie: {len(security_updates)} balíkov'
        
        return result_data
        
    except subprocess.TimeoutExpired:
        return {
            'status': 'ERROR',
            'message': 'Timeout pri vykonávaní príkazu apt',
            'error': 'Príkaz trval príliš dlho - možno problém so sieťou alebo repozitármi'
        }
    except PermissionError:
        return {
            'status': 'ERROR',
            'message': 'Nedostatočné oprávnenia',
            'error': 'Pre aktualizáciu zoznamu balíkov sú potrebné sudo oprávnenia',
            'recommendation': 'Spustite skript s sudo oprávneniami'
        }
    except FileNotFoundError:
        return {
            'status': 'ERROR',
            'message': 'Príkaz apt nebol nájdený',
            'error': 'Systém neobsahuje APT package manager',
            'note': 'Tento test je určený pre Debian/Ubuntu systémy'
        }
    except Exception as e:
        return {
            'status': 'ERROR',
            'message': 'Neočakávaná chyba pri kontrole aktualizácií',
            'error': str(e)
        }


def parse_upgradable_packages(output):
    packages = []
    lines = output.split('\n')
    
    for line in lines:
        if 'Listing...' in line or not line.strip():
            continue
        
        match = re.match(r'^([^\s/]+)/?([^\s]*)\s+([^\s]+)\s+([^\s]+)\s*(?:\[upgradable from:\s*([^\]]+)\])?', line)
        
        if match:
            package_name = match.group(1)
            suite = match.group(2) if match.group(2) else 'unknown'
            new_version = match.group(3)
            arch = match.group(4)
            old_version = match.group(5) if match.group(5) else 'unknown'
            
            packages.append({
                'name': package_name,
                'suite': suite,
                'current_version': old_version,
                'available_version': new_version,
                'architecture': arch
            })
        else:
            parts = line.split()
            if len(parts) >= 1:
                package_name = parts[0].split('/')[0]
                packages.append({
                    'name': package_name,
                    'raw': line.strip()
                })
    
    return packages


def check_security_updates():
    """
    Kontroluje špecificky bezpečnostné aktualizácie pomocou unattended-upgrades
    alebo apt-get upgrade --simulate.
    """
    security_packages = []
    
    try:
        result = subprocess.run(
            ['apt-get', '--just-print', 'upgrade'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            output = result.stdout
            for line in output.split('\n'):
                if 'security' in line.lower() and 'Inst' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        security_packages.append(parts[1])
        
    except Exception as e:
        print(f"Chyba pri kontrole bezpečnostných aktualizácií: {e}")
    
    return security_packages


if __name__ == "__main__":
    test_params = {
        'max_updates_warning': 10,
        'max_updates_critical': 50,
        'check_security_only': False
    }
    result = run(test_params)
    print(f"\nVýsledok testu:")
    for key, value in result.items():
        if isinstance(value, list) and len(value) > 5:
            print(f"  {key}: [{len(value)} položiek]")
            for item in value[:5]:
                print(f"    - {item}")
            print(f"    ... (a ďalšie)")
        else:
            print(f"  {key}: {value}")