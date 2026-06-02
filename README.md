# Automated auditing tool for Unix operating systems

Modulárny auditovací nástroj pre Unix/Linux systémy. Projekt obsahuje **Python verziu** (modulárny framework + testy)
a zároveň aj **Bash testy** (v zložke `tests/`).

> Poznámka: `config.json` môže byť v rôznych fázach práce nastavený pre Bash alebo Python testy.
> Pri spúšťaní vždy skontroluj, či pole `tests[].file` odkazuje na existujúce súbory.

## Prehľad

- **Python runner**: `main.py`
- **Python testy**: `tests/*.py` (každý modul musí mať funkciu `run(params)` alebo `run(params=None)`)
- **Bash testy**: `tests/*.sh`
- **Konfigurácia**: `config.json`
- **Výstup**:
  - Python: `enumeration_results.json` (štruktúrovaný JSON s výsledkami + `__summary__`)
  - Bash: závisí od konkrétneho runneru / implementácie

## Požiadavky

### Python verzia

- Python 3.10+ (odporúčané)
- (voliteľne) `paramiko` len ak chceš SSH cez heslo

### Bash testy

- Bash
- nástroje podľa konkrétnych testov (napr. `apt`, `systemctl`, `ufw`, `ss`, `iptables`, `nft`, …)

## Spustenie (Python)

V koreňovej zložke projektu:

```bash
python3 main.py
```

Použitie vlastnej konfigurácie:

```bash
python3 main.py ./config.json
```

### Vzdialený režim (SSH)

Python verzia podporuje presmerovanie volaní `subprocess.run` cez SSH.

Kľúčový scenár (SSH key):

```bash
python3 main.py ./config.json --remote 192.168.1.10 --ssh-user user --ssh-key ~/.ssh/id_rsa
```

Heslo (vyžaduje `paramiko`):

```bash
pip install paramiko
python3 main.py ./config.json --remote 192.168.1.10 --ssh-user user --ssh-password-env SSH_PASSWORD
```

## Konfigurácia (Python)

Základné polia v `config.json`:

- `tests_directory` (default `tests`)
- `save_results` (true/false)
- `output_file` (default `enumeration_results.json`)
- `tests[]` (zoznam testov)

Každý test:

- `name`: názov testu
- `file`: názov Python súboru v `tests/` (napr. `firewallCheck.py`)
- `enabled`: true/false
- `parameters`: objekt parametrov, ktorý sa odovzdá do `run(params)`

Príklad jednej položky:

```json
{
  "name": "Firewall Status Check",
  "file": "firewallCheck.py",
  "enabled": true,
  "description": "Kontrola stavu firewallu (ufw)",
  "parameters": {
    "require_active": true,
    "check_rules": true
  }
}
```

## Výstupy (Python)

Ak `save_results: true`, vytvorí sa JSON (default `enumeration_results.json`) so štruktúrou:

- per-test:
  - `status`: `success` alebo `error` (stav spustenia modulu)
  - `timestamp`: čas behu
  - `result`: návratová hodnota `run(params)` (typicky `status` + findings/fields)
- `__summary__`:
  - `tests_count`, `score`, `max_score` a pravidlá penalizácie podľa `severity`

## Ako pridať vlastný Python test

Pozri návod: `docs/CREATE_PYTHON_TEST_TUTORIAL.md`.

## Troubleshooting (Python)

- **`File not found` / test sa nenačíta**: skontroluj `tests[].file` v `config.json` a existenciu súboru v `tests/`
- **`Permission denied`**: niektoré príkazy/súbory vyžadujú root; spusti `sudo python3 main.py ...`
- **Remote režim**: niektoré moduly čítajú súbory priamo (lokálne). Pre kompatibilitu s `--remote` preferuj čítanie cez `subprocess.run(["sh","-lc","cat ..."])` (viď tutorial).