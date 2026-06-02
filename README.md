# Automated auditing tool for Unix operating systems

Modulárny auditovací nástroj pre Unix/Linux systémy postavený na jednoduchom „enumeration frameworku“.
Audit je definovaný konfiguračným súborom a realizovaný samostatnými testami v zložke `tests/`.

## Prehľad

- **Spúšťací skript**: `main.sh`
- **Konfigurácia auditu**: `config.json`
- **Testy**: `tests/*.sh` (každý test je samostatný shell skript s funkciou `run()`)
- **Výstup**: JSON súbor (napr. `enumeration_results.json`) so stavom a konzolovým výstupom testov

## Požiadavky

- Bash (Linux/Unix prostredie)
- `jq` (povinné; parsovanie `config.json`)
- Typické systémové nástroje podľa konkrétnych testov (napr. `apt-get`, `systemctl`, `ufw`, `ss`, `iptables`, `nft`, …)

Na Ubuntu:

```bash
sudo apt update
sudo apt install -y jq
```

## Rýchly štart

V koreňovej zložke projektu:

```bash
chmod +x ./main.sh
./main.sh
```

Ak chceš použiť iný konfiguračný súbor:

```bash
./main.sh ./config.json
```

## Konfigurácia (`config.json`)

Základné polia:

- **`tests_directory`**: zložka s testami (default `tests`)
- **`save_results`**: či sa má uložiť výstup (true/false)
- **`output_file`**: cesta k výslednému JSON súboru
- **`tests[]`**: zoznam testov

Každý test má:

- **`name`**: názov zobrazený v konzole a vo výstupe
- **`file`**: názov testu (pozri poznámku nižšie)
- **`enabled`**: true/false
- **`description`**: popis
- **`parameters`**: ľubovoľný objekt s parametrami testu

### Poznámka k poľu `file`

`main.sh` aktuálne **automaticky prevádza** hodnotu `file` z prípony `.py` na `.sh`
(napr. `firewallCheck.py` → `tests/firewallCheck.sh`).

Odporúčanie: v `config.json` používaj rovnaký názov ako v `tests/` a drž sa konvencie projektu
(`SomethingCheck.py` v `file`, reálne `SomethingCheck.sh` v `tests/`).

Príklad:

```json
{
  "name": "Firewall Status Check",
  "file": "firewallCheck.py",
  "enabled": true,
  "description": "Checks UFW, iptables and nftables firewall status and rules",
  "parameters": {
    "require_active": true,
    "check_rules": true
  }
}
```

## Výstupy

Ak je `save_results: true`, po behu sa vytvorí JSON súbor (default `enumeration_results.json`).
Obsahuje pre každý test:

- `status`: `success` alebo `error` (či skript dobehol bez chyby)
- `output`: celý textový výstup testu (stdout/stderr)
- `timestamp`: ISO čas behu testu

Poznámka: jednotlivé testy typicky vypisujú vlastnú hlavičku a riadok `Status: <pass|warn|fail|critical>`.
Tento „vnútorný status“ je určený pre ľudské čítanie a/alebo ďalšie spracovanie v budúcnosti.

## Spúšťanie ako root (sudo)

Niektoré testy vyžadujú zvýšené oprávnenia (napr. čítanie určitých súborov, enumerácia pravidiel firewallu).
Ak vidíš neúplné výsledky alebo `permission denied`, spusti audit s `sudo`:

```bash
sudo ./main.sh
```

## Troubleshooting

- **`jq: command not found`**: doinštaluj `jq` (Ubuntu: `sudo apt install jq`)
- **Test sa nenačíta**: `main.sh` vyžaduje, aby test existoval v `tests/` a obsahoval funkciu `run()`
- **Test hlási chýbajúci nástroj**: nainštaluj závislosť na auditovanom systéme (napr. `ufw`, `iproute2`)
- **Audit trvá dlho**: niektoré testy spúšťajú príkazy nad väčším množstvom dát (balíky, služby, filesystem)

## Ako pridať vlastný test

Pozri samostatný návod: `docs/CREATE_TEST_TUTORIAL.md`.