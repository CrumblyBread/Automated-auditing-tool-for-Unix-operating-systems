#!/usr/bin/env python3
import subprocess
import stat

import shlex

def _sh(cmd: str, timeout: int | None = None):
    return subprocess.run(["sh", "-lc", cmd], capture_output=True, text=True, timeout=timeout)

def _path_exists(path: str) -> bool:
    return _sh(f"test -e {shlex.quote(path)}").returncode == 0

def _list_dirs(path: str):
    # Return list of full paths to immediate subdirectories
    r = _sh(f"ls -1A {shlex.quote(path)} 2>/dev/null")
    if r.returncode != 0:
        return None
    entries = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    out = []
    for e in entries:
        full = f"{path.rstrip('/')}/{e}"
        if _sh(f"test -d {shlex.quote(full)}").returncode == 0:
            out.append(full)
    return out

def _stat_mode_uid(path: str):
    r = _sh(f"stat -c '%a %u %U' {shlex.quote(path)} 2>/dev/null")
    if r.returncode != 0:
        return (None, None, None)
    parts = (r.stdout or "").strip().strip("'").split()
    if len(parts) < 2:
        return (None, None, None)
    mode_s = parts[0]
    uid_s = parts[1]
    user_s = parts[2] if len(parts) >= 3 else None
    if not mode_s.isdigit() or not uid_s.isdigit():
        return (None, None, None)
    return (int(mode_s, 10), int(uid_s, 10), user_s)


def run(params):
    print("Spúšťam test prístupových práv v domovských adresároch...")
    
    home_base_dir = params.get('home_directory', '/home')
    check_world_readable = params.get('check_world_readable', True)
    check_world_writable = params.get('check_world_writable', True)
    check_group_writable = params.get('check_group_writable', True)
    max_permissions = params.get('max_permissions', '755')
    
    try:
        if not _path_exists(home_base_dir):
            return {
                'status': 'ERROR',
                'message': f'Adresár {home_base_dir} neexistuje',
                'error': 'Nemožno kontrolovať domovské adresáre'
            }
        
        home_dirs = []
        try:
            dirs = _list_dirs(home_base_dir)
            if dirs is None:
                raise PermissionError("Cannot list directory")
            home_dirs.extend(dirs)
        except PermissionError:
            return {
                'status': 'ERROR',
                'message': f'Nedostatočné oprávnenia na čítanie {home_base_dir}',
                'error': 'Spustite test s dostatočnými oprávneniami',
                'recommendation': 'Spustite skript s sudo oprávneniami'
            }
        
        if not home_dirs:
            return {
                'status': 'WARNING',
                'message': f'Nenájdené žiadne domovské adresáre v {home_base_dir}',
                'home_directory': home_base_dir
            }
        
        print(f"Našiel som {len(home_dirs)} domovských adresárov")
        
        insecure_dirs = []
        secure_dirs = []
        
        for home_dir in home_dirs:
            result = check_directory_permissions(
                home_dir, 
                check_world_readable,
                check_world_writable,
                check_group_writable,
                max_permissions
            )
            
            if result['is_insecure']:
                insecure_dirs.append(result)
                print(f"Nebezpečné oprávnenia: {home_dir} - {result['permissions_octal']}")
            else:
                secure_dirs.append(result)
                print(f"Bezpečné oprávnenia: {home_dir} - {result['permissions_octal']}")
        
        if insecure_dirs:
            issues_summary = []
            for dir_info in insecure_dirs:
                issues_summary.append({
                    'path': dir_info['path'],
                    'permissions': dir_info['permissions_octal'],
                    'issues': dir_info['issues'],
                    'owner': dir_info.get('owner', 'unknown')
                })
            
            return {
                'status': 'FAIL',
                'message': f'Zistené nebezpečné prístupové práva v {len(insecure_dirs)} domovských adresároch',
                'insecure_directories_count': len(insecure_dirs),
                'secure_directories_count': len(secure_dirs),
                'insecure_directories': issues_summary,
                'security_risk': 'Príliš permisívne nastavenia môžu viesť k prístupu neoprávnených používateľov k súkromným dátam',
                'severity': 'HIGH',
                'recommendation': 'Upravte prístupové práva domovských adresárov na bezpečné hodnoty (napr. 750 alebo 700)',
                'commands': [
                    f'sudo chmod 750 {insecure_dirs[0]["path"]}',
                    'sudo chmod 750 /home/*',
                    'sudo chmod 700 /home/username'
                ],
                'impact': 'Nedostatky v prístupových právach môžu umožniť neautorizovaný prístup k súkromným dátam používateľov'
            }
        else:
            return {
                'status': 'PASS',
                'message': 'Všetky domovské adresáre mají bezpečné prístupové práva',
                'checked_directories_count': len(home_dirs),
                'secure_directories': [
                    {
                        'path': d['path'],
                        'permissions': d['permissions_octal'],
                        'owner': d.get('owner', 'unknown')
                    } for d in secure_dirs
                ],
                'severity': 'INFO'
            }
        
    except Exception as e:
        return {
            'status': 'ERROR',
            'message': 'Neočakávaná chyba pri kontrole prístupových práv',
            'error': str(e)
        }


def check_directory_permissions(dir_path, check_world_readable, check_world_writable, 
                                 check_group_writable, max_permissions):
    result = {
        'path': dir_path,
        'is_insecure': False,
        'issues': []
    }
    
    try:
        mode_octal, uid, user = _stat_mode_uid(dir_path)
        if mode_octal is None:
            raise RuntimeError("stat failed")
        # Convert e.g. 750 -> bits int
        mode = int(str(mode_octal), 8)
        
        permissions_octal = oct(stat.S_IMODE(mode))[2:]
        result['permissions_octal'] = permissions_octal
        result['permissions_symbolic'] = stat.filemode(mode)
        
        if user:
            result['owner'] = user
        elif uid is not None:
            result['owner'] = f'UID:{uid}'
        else:
            result['owner'] = 'unknown'
        
        if check_world_readable and mode & stat.S_IROTH:
            result['is_insecure'] = True
            result['issues'].append('Adresár je čitateľný pre všetkých používateľov (other readable)')
        
        if check_world_writable and mode & stat.S_IWOTH:
            result['is_insecure'] = True
            result['issues'].append('Adresár je zapisovateľný pre všetkých používateľov (other writable) - KRITICKÉ!')
        
        if mode & stat.S_IXOTH and (mode & stat.S_IROTH or mode & stat.S_IWOTH):
            result['is_insecure'] = True
            result['issues'].append('Ostatní používatelia majú prístup do adresára (other executable)')
        
        if check_group_writable and mode & stat.S_IWGRP:
            result['is_insecure'] = True
            result['issues'].append('Skupina má právo zápisu do adresára (group writable)')
        
        permissions_int = int(permissions_octal, 8)
        max_permissions_int = int(max_permissions, 8)
        
        if permissions_int > max_permissions_int:
            result['is_insecure'] = True
            result['issues'].append(f'Oprávnenia ({permissions_octal}) presahujú maximálnu odporúčanú hodnotu ({max_permissions})')
        
        if permissions_octal == '777':
            result['is_insecure'] = True
            result['issues'].append('KRITICKÉ: Adresár má úplne otvorené oprávnenia (777) - prístupný pre všetkých!')
        
    except PermissionError:
        result['is_insecure'] = False
        result['error'] = 'Nedostatočné oprávnenia na kontrolu tohto adresára'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def get_recommended_permissions(current_permissions):
    if current_permissions in ['777', '775', '755', '774', '773', '771', '770']:
        return '750' 
    elif current_permissions in ['700', '750']:
        return current_permissions  
    else:
        return '750' 


if __name__ == "__main__":
    test_params = {
        'home_directory': '/home',
        'check_world_readable': True,
        'check_world_writable': True,
        'check_group_writable': True,
        'max_permissions': '755'
    }
    result = run(test_params)
    print(f"\nVýsledok testu:")
    for key, value in result.items():
        if isinstance(value, list) and len(value) > 3:
            print(f"  {key}: [{len(value)} položiek]")
            for item in value[:3]:
                print(f"    - {item}")
            print(f"    ... (a ďalšie)")
        else:
            print(f"  {key}: {value}")