#!/usr/bin/env python3
import subprocess
import re


def run(params):
    print("Spúšťam test stavu firewallu...")
    
    check_rules = params.get('check_rules', False)
    require_active = params.get('require_active', True)
    
    try:
        ufw_check = subprocess.run(
            ['which', 'ufw'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if ufw_check.returncode != 0:
            return {
                'status': 'ERROR',
                'message': 'UFW firewall nie je nainštalovaný',
                'error': 'Nástroj ufw nebol nájdený v systéme',
                'recommendation': 'Nainštalujte ufw pomocou: sudo apt install ufw',
                'severity': 'HIGH'
            }
        
        result = subprocess.run(
            ['sudo', 'ufw', 'status'],
            capture_output=True,
            text=True,
            timeout=500
        )
        
        if result.returncode != 0:
            return {
                'status': 'ERROR',
                'message': 'Nepodarilo sa získať stav firewallu',
                'error': result.stderr.strip(),
                'note': 'Možno je potrebné spustiť skript s sudo oprávneniami'
            }
        
        output = result.stdout.strip()
        print(f"Výstup ufw status:\n{output}")
        
        is_active = 'Status: active' in output.lower() or 'stav: aktívny' in output.lower()
        is_inactive = 'Status: inactive' in output.lower() or 'stav: neaktívny' in output.lower()
        
        rules = []
        if is_active and check_rules:
            rules = extract_firewall_rules(output)
        
        if not is_active and require_active:
            return {
                'status': 'FAIL',
                'message': 'Firewall nie je aktivovaný',
                'firewall_status': 'inactive',
                'security_risk': 'Systém je zraniteľný voči neoprávneným sieťovým prístupom',
                'recommendation': 'Aktivujte firewall a definujte základné pravidlá prístupu',
                'commands': [
                    'sudo ufw default deny incoming',
                    'sudo ufw default allow outgoing',
                    'sudo ufw allow ssh',
                    'sudo ufw enable'
                ],
                'severity': 'HIGH',
                'impact': 'Chýbajúca základná ochrana sieťovej vrstvy - častá zraniteľnosť v predvolených inštaláciách Ubuntu'
            }
        elif is_active:
            result_data = {
                'status': 'PASS',
                'message': 'Firewall je aktívny',
                'firewall_status': 'active',
                'severity': 'INFO'
            }
            
            if check_rules and rules:
                result_data['active_rules'] = rules
                result_data['rules_count'] = len(rules)
                
                if len(rules) == 0:
                    result_data['status'] = 'WARNING'
                    result_data['message'] = 'Firewall je aktívny, ale nie sú definované žiadne pravidlá'
                    result_data['recommendation'] = 'Definujte pravidlá firewallu pre potrebné služby'
            
            return result_data
        else:
            return {
                'status': 'WARNING',
                'message': 'Nepodarilo sa jednoznačne určiť stav firewallu',
                'firewall_output': output,
                'recommendation': 'Manuálne overte stav firewallu pomocou: sudo ufw status verbose'
            }
            
    except subprocess.TimeoutExpired:
        return {
            'status': 'ERROR',
            'message': 'Timeout pri vykonávaní príkazu ufw',
            'error': 'Príkaz trval príliš dlho'
        }
    except PermissionError:
        return {
            'status': 'ERROR',
            'message': 'Nedostatočné oprávnenia',
            'error': 'Pre kontrolu stavu firewallu sú potrebné sudo oprávnenia',
            'recommendation': 'Spustite skript s sudo oprávneniami'
        }
    except FileNotFoundError:
        return {
            'status': 'ERROR',
            'message': 'Príkaz ufw alebo sudo nebol nájdený',
            'error': 'Systém neobsahuje potrebné nástroje'
        }
    except Exception as e:
        return {
            'status': 'ERROR',
            'message': 'Neočakávaná chyba pri teste firewallu',
            'error': str(e)
        }


def extract_firewall_rules(output):
    rules = []
    lines = output.split('\n')
    
    in_rules_section = False
    for line in lines:
        if '---' in line or 'To' in line and 'Action' in line:
            in_rules_section = True
            continue
        
        if in_rules_section and line.strip():
            parts = line.split()
            if len(parts) >= 2:
                rules.append({
                    'raw': line.strip(),
                    'service': parts[0] if len(parts) > 0 else 'unknown'
                })
    
    return rules


def check_ufw_without_sudo(params):
    try:
        result = subprocess.run(
            ['ufw', 'status'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if 'must be root' in result.stderr.lower() or 'permission denied' in result.stderr.lower():
            return {
                'status': 'WARNING',
                'message': 'Nie je možné overiť stav firewallu bez sudo oprávnení',
                'ufw_installed': True,
                'recommendation': 'Spustite test s sudo oprávneniami pre úplnú kontrolu'
            }
    except Exception:
        pass
    
    return None


if __name__ == "__main__":
    test_params = {
        'require_active': True,
        'check_rules': True
    }
    result = run(test_params)
    print(f"\nVýsledok testu:")
    for key, value in result.items():
        print(f"  {key}: {value}")