#!/usr/bin/env python3
import subprocess
import os
import shutil


def run(params):
    print("Spúšťam test stavu MAC systému (AppArmor/SELinux)...")
    
    preferred_mac = params.get('preferred_mac', 'apparmor')  # apparmor alebo selinux
    require_active = params.get('require_active', True)
    check_profiles = params.get('check_profiles', True)
    
    mac_system = detect_mac_system()
    
    if mac_system == 'none':
        return {
            'status': 'SKIPPED',
            'message': 'Žiadny MAC systém (AppArmor/SELinux) nie je nainštalovaný',
            'mac_system': 'none',
            'recommendation': 'Nainštalujte a aktivujte AppArmor alebo SELinux pre zvýšenie bezpečnosti',
            'severity': 'HIGH',
            'note': 'Absencia MAC ochrany výrazne znižuje bezpečnosť systému',
            'commands': [
                'sudo apt install apparmor apparmor-utils',
                'sudo systemctl enable apparmor',
                'sudo systemctl start apparmor'
            ]
        }
    
    print(f"Detegovaný MAC systém: {mac_system}")
    
    if mac_system == 'apparmor':
        return check_apparmor(require_active, check_profiles)
    elif mac_system == 'selinux':
        return check_selinux(require_active)
    else:
        return {
            'status': 'ERROR',
            'message': 'Neznámy MAC systém',
            'mac_system': mac_system
        }


def detect_mac_system():
    if shutil.which('aa-status') or os.path.exists('/sys/kernel/security/apparmor'):
        return 'apparmor'
    
    if shutil.which('getenforce') or os.path.exists('/etc/selinux/config'):
        return 'selinux'
    
    return 'none'


def check_apparmor(require_active, check_profiles):
    try:
        if not shutil.which('aa-status'):
            return {
                'status': 'ERROR',
                'message': 'AppArmor je prítomný, ale príkaz aa-status nie je dostupný',
                'mac_system': 'apparmor',
                'recommendation': 'Nainštalujte apparmor-utils: sudo apt install apparmor-utils'
            }
        
        result = subprocess.run(
            ['sudo', 'aa-status'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            stderr_output = result.stderr.strip().lower()
            
            if 'apparmor filesystem is not mounted' in stderr_output or \
               'apparmor is not enabled' in stderr_output:
                return {
                    'status': 'FAIL',
                    'message': 'AppArmor nie je aktívny',
                    'mac_system': 'apparmor',
                    'apparmor_status': 'inactive',
                    'security_risk': 'Absencia MAC (Mandatory Access Control) ochrany výrazne znižuje schopnosť systému obmedziť škody pri kompromitácii aplikácií',
                    'severity': 'HIGH',
                    'recommendation': 'Aktivujte AppArmor pre zvýšenie bezpečnosti systému',
                    'commands': [
                        'sudo systemctl enable apparmor',
                        'sudo systemctl start apparmor',
                        'sudo aa-enforce /etc/apparmor.d/*'
                    ],
                    'impact': 'Bez MAC ochrany môžu kompromitované aplikácie získať neobmedzený prístup k systémovým zdrojom'
                }
            else:
                return {
                    'status': 'ERROR',
                    'message': 'Chyba pri kontrole stavu AppArmor',
                    'error': result.stderr.strip(),
                    'note': 'Možno je potrebné spustiť skript s sudo oprávneniami'
                }
        
        output = result.stdout
        apparmor_info = parse_apparmor_status(output)
        
        print(f"AppArmor je aktívny")
        print(f"Profily v enforce mode: {apparmor_info['profiles_enforce']}")
        print(f"Profily v complain mode: {apparmor_info['profiles_complain']}")
        
        if apparmor_info['is_loaded']:
            result_data = {
                'status': 'PASS',
                'message': 'AppArmor je aktívny a načítaný',
                'mac_system': 'apparmor',
                'apparmor_status': 'active',
                'profiles_loaded': apparmor_info['profiles_loaded'],
                'profiles_enforce': apparmor_info['profiles_enforce'],
                'profiles_complain': apparmor_info['profiles_complain'],
                'processes_with_profiles': apparmor_info['processes_with_profiles'],
                'severity': 'INFO'
            }
            
            if apparmor_info['profiles_complain'] > 0:
                result_data['status'] = 'WARNING'
                result_data['message'] = f'AppArmor je aktívny, ale {apparmor_info["profiles_complain"]} profilov je v complain mode'
                result_data['recommendation'] = 'Zvážte aktivovanie complain profilov do enforce mode pre plnú ochranu'
                result_data['severity'] = 'MEDIUM'
            
            if apparmor_info['profiles_loaded'] == 0:
                result_data['status'] = 'WARNING'
                result_data['message'] = 'AppArmor je aktívny, ale nie sú načítané žiadne profily'
                result_data['recommendation'] = 'Načítajte AppArmor profily pre kritické aplikácie'
                result_data['severity'] = 'MEDIUM'
            
            if check_profiles and apparmor_info['profile_names']:
                result_data['active_profiles'] = apparmor_info['profile_names'][:10]
                if len(apparmor_info['profile_names']) > 10:
                    result_data['note'] = f'Zobrazených prvých 10 z {len(apparmor_info["profile_names"])} profilov'
            
            return result_data
        else:
            return {
                'status': 'FAIL',
                'message': 'AppArmor nie je správne načítaný',
                'mac_system': 'apparmor',
                'apparmor_status': 'loaded_but_inactive',
                'severity': 'HIGH',
                'recommendation': 'Reštartujte AppArmor službu'
            }
        
    except subprocess.TimeoutExpired:
        return {
            'status': 'ERROR',
            'message': 'Timeout pri vykonávaní príkazu aa-status',
            'error': 'Príkaz trval príliš dlho'
        }
    except PermissionError:
        return {
            'status': 'ERROR',
            'message': 'Nedostatočné oprávnenia',
            'error': 'Pre kontrolu stavu AppArmor sú potrebné sudo oprávnenia',
            'recommendation': 'Spustite skript s sudo oprávneniami'
        }
    except Exception as e:
        return {
            'status': 'ERROR',
            'message': 'Neočakávaná chyba pri kontrole AppArmor',
            'error': str(e)
        }


def parse_apparmor_status(output):
    info = {
        'is_loaded': False,
        'profiles_loaded': 0,
        'profiles_enforce': 0,
        'profiles_complain': 0,
        'processes_with_profiles': 0,
        'profile_names': []
    }
    
    lines = output.split('\n')
    
    for line in lines:
        line_lower = line.lower()
        
        if 'apparmor module is loaded' in line_lower:
            info['is_loaded'] = True
        
        if 'profiles are loaded' in line_lower or 'profiles loaded' in line_lower:
            parts = line.split()
            if parts and parts[0].isdigit():
                info['profiles_loaded'] = int(parts[0])
        
        if 'profiles are in enforce mode' in line_lower:
            parts = line.split()
            if parts and parts[0].isdigit():
                info['profiles_enforce'] = int(parts[0])
        
        if 'profiles are in complain mode' in line_lower:
            parts = line.split()
            if parts and parts[0].isdigit():
                info['profiles_complain'] = int(parts[0])
        
        if 'processes have profiles defined' in line_lower or 'processes are defined' in line_lower:
            parts = line.split()
            if parts and parts[0].isdigit():
                info['processes_with_profiles'] = int(parts[0])
        
        if line.startswith('   /') or line.startswith('      /'):
            profile_name = line.strip()
            if profile_name:
                info['profile_names'].append(profile_name)
    
    return info


def check_selinux(require_active):
    try:
        result = subprocess.run(
            ['getenforce'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode != 0:
            return {
                'status': 'ERROR',
                'message': 'Chyba pri kontrole stavu SELinux',
                'error': result.stderr.strip()
            }
        
        selinux_status = result.stdout.strip().lower()
        
        if selinux_status == 'enforcing':
            return {
                'status': 'PASS',
                'message': 'SELinux je aktívny v enforcing mode',
                'mac_system': 'selinux',
                'selinux_mode': 'enforcing',
                'severity': 'INFO'
            }
        elif selinux_status == 'permissive':
            return {
                'status': 'WARNING',
                'message': 'SELinux je v permissive mode (len loguje porušenia)',
                'mac_system': 'selinux',
                'selinux_mode': 'permissive',
                'recommendation': 'Aktivujte SELinux do enforcing mode',
                'severity': 'MEDIUM',
                'commands': ['sudo setenforce 1']
            }
        elif selinux_status == 'disabled':
            return {
                'status': 'FAIL',
                'message': 'SELinux je deaktivovaný',
                'mac_system': 'selinux',
                'selinux_mode': 'disabled',
                'security_risk': 'Absencia MAC ochrany',
                'recommendation': 'Aktivujte SELinux v /etc/selinux/config a reštartujte systém',
                'severity': 'HIGH'
            }
        else:
            return {
                'status': 'WARNING',
                'message': f'Neznámy stav SELinux: {selinux_status}',
                'mac_system': 'selinux',
                'selinux_mode': selinux_status
            }
        
    except FileNotFoundError:
        return {
            'status': 'ERROR',
            'message': 'Príkaz getenforce nebol nájdený',
            'error': 'SELinux nástroje nie sú nainštalované'
        }
    except Exception as e:
        return {
            'status': 'ERROR',
            'message': 'Neočakávaná chyba pri kontrole SELinux',
            'error': str(e)
        }


if __name__ == "__main__":
    test_params = {
        'preferred_mac': 'apparmor',
        'require_active': True,
        'check_profiles': True
    }
    result = run(test_params)
    print(f"\nVýsledok testu:")
    for key, value in result.items():
        if isinstance(value, list) and len(value) > 5:
            print(f"  {key}: [{len(value)} položiek]")
            for item in value[:5]:
                print(f"    - {item}")
        else:
            print(f"  {key}: {value}")