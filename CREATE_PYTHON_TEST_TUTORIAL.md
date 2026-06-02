# Tutorial: Ako vytvoriť vlastný test (Python verzia)

Tento dokument popisuje, ako pridať nový test do **Python** verzie frameworku (`main.py`).
Testy sú uložené v zložke `tests/` a každý test je samostatný Python modul s funkciou `run(...)`.

## 1) Ako framework spúšťa testy

`main.py`:

- načíta konfiguráciu (default `config.json`)
- pre každý zapnutý test (`enabled: true`) načíta modul zo súboru `tests/<file>`
- vyžaduje, aby modul obsahoval funkciu `run`
- zavolá `run(params)`, kde `params` je slovník z `tests[].parameters`
- výsledok uloží do `enumeration_results.json`
- doplní `severity` do jednotnej škály a vypočíta skóre (`__summary__`)

## 2) Minimálna šablóna testu

Vytvor nový súbor, napríklad `tests/myCustomCheck.py`:

```python
#!/usr/bin/env python3

def run(params=None):
    if params is None:
        params = {}

    path = params.get("path", "/etc/passwd")

    # Odporúčané statusy v tomto projekte: pass|warn|fail|critical|error
    if path:
        status = "pass"
        findings = [f"PASS: path configured: {path}"]
    else:
        status = "fail"
        findings = ["FAIL: no path provided"]

    return {
        "test_name": "My Custom Check",
        "status": status,
        "findings": findings,
    }
```

## 3) Pridanie testu do `config.json`

Do poľa `tests` pridaj položku:

```json
{
  "name": "My Custom Check",
  "file": "myCustomCheck.py",
  "enabled": true,
  "description": "Example: basic template check",
  "parameters": {
    "path": "/etc/passwd"
  }
}
```

Potom spusti:

```bash
python3 main.py ./config.json
```

## 4) Návratová štruktúra a statusy

Framework akceptuje ľubovoľný `dict`, ale pre konzistentnosť odporúčame:

- `test_name`: názov testu
- `status`: jeden z
  - `pass` (bez nálezu)
  - `warn` / `warning` (odporúčanie / potenciálny problém)
  - `fail` (zistený problém)
  - `critical` (kritický problém)
  - `error` (test sa nedá vykonať; napr. chýbajúce oprávnenia/nástroj)
- `findings`: zoznam textových zistení

`main.py` následne:

- premapuje `status` → jednotnú `severity` škálu: `None|Low|Medium|High|Critical`
- vypočíta skóre a uloží ho do `__summary__`

## 5) Parametre testu (`params`)

`params` je obyčajný `dict`. Odporúčania:

- vždy poskytni default hodnoty (`params.get("x", default)`)
- validuj typy (napr. `int`, `bool`, `list`)
- nepadni na výnimke pri „očakávaných“ stavoch; vráť `status: error` + vysvetlenie

## 6) Kompatibilita s `--remote` (veľmi dôležité)

Vzdialený režim v `main.py` funguje tak, že **presmeruje `subprocess.run(...)` cez SSH**.

To má dva dôsledky:

1. **Príkazy spustené cez `subprocess.run` prebehnú na vzdialenom stroji.**
2. **Priame čítanie súborov cez `open("/etc/...")` prebehne lokálne** (na riadiacom stroji),
   čo je pri `--remote` často nesprávne.

### Správny spôsob čítania súboru (remote-safe)

Použi čítanie cez shell príkaz:

```python
import subprocess
import shlex

def read_remote_file(path: str) -> str:
    r = subprocess.run(
        ["sh", "-lc", f"cat {shlex.quote(path)}"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError((r.stderr or "").strip() or f"Failed to read {path}")
    return r.stdout
```

Tento vzor používa napríklad `tests/sshConfigCheck.py`.

### Odporúčanie pre testy

- ak test potrebuje súbor zo systému (`/etc/...`), čítaj ho cez `subprocess.run(["sh","-lc","cat ..."])`
- ak test potrebuje príkaz (`uname`, `systemctl`, `ss`, …), spúšťaj ho vždy cez `subprocess.run`
- pri `sudo` závislých príkazoch buď explicitný (vo findings uveď, že treba root), alebo používaj
  príkazy, ktoré sú čitateľné bez `sudo` (ak je to možné)

## 7) Príklad „štýlu“ testu v tomto projekte

Ako referenciu si pozri:

- `tests/sshConfigCheck.py` (remote-safe čítanie `sshd_config`)
- `tests/securityUpdatesCheck.py` (apt/dpkg logika)
- `tests/userAccountsCheck.py` (kombinácia príkazov + parsovanie)

