# Tutorial: Ako vytvoriť vlastný test

Tento dokument popisuje, ako pridať nový test do auditovacieho frameworku.
Testy sú uložené v zložke `tests/` a sú implementované ako samostatné Bash skripty.

## 1) Ako framework spúšťa testy

Skript `main.sh`:

- načíta `config.json` pomocou `jq`
- pre každý zapnutý test (`enabled: true`) nájde zodpovedajúci skript v `tests/`
- skript **načíta** (`source`) a zavolá funkciu `run`
- parametre testu z `config.json` sprístupní cez premennú prostredia `TEST_PARAMS` ako JSON reťazec

Z toho vyplývajú dve pravidlá:

1. Test musí byť súbor `tests/<nieco>.sh`.
2. Test musí definovať funkciu `run()` (bez argumentov) a v nej vykonať audit.

## 2) Šablóna testu

Vytvor nový súbor, napríklad `tests/myCustomCheck.sh`.

```bash
#!/usr/bin/env bash
set -euo pipefail

run() {
  # TEST_PARAMS obsahuje JSON s parametrami z config.json
  # Použi jq na bezpečné načítanie parametrov s default hodnotami.
  local required_path
  required_path="$(jq -r '.required_path // "/etc/passwd"' <<<"${TEST_PARAMS:-{}}")"

  local status="pass"
  local findings=()

  if [[ -f "$required_path" ]]; then
    findings+=("PASS: File exists: $required_path")
  else
    findings+=("FAIL: File missing: $required_path")
    status="fail"
  fi

  echo ""
  echo "=== My Custom Check ==="
  echo "Status: ${status}"
  for f in "${findings[@]}"; do echo "  ${f}"; done
}
```

Potom:

```bash
chmod +x tests/myCustomCheck.sh
```

## 3) Pridanie testu do `config.json`

Do poľa `tests` pridaj novú položku:

```json
{
  "name": "My Custom Check",
  "file": "myCustomCheck.py",
  "enabled": true,
  "description": "Example: verifies a path exists",
  "parameters": {
    "required_path": "/etc/passwd"
  }
}
```

### Poznámka k poľu `file`

`main.sh` prevádza `.py` → `.sh`, takže `myCustomCheck.py` smeruje na `tests/myCustomCheck.sh`.
Ak nechceš používať túto konvenciu, drž sa existujúceho vzoru v projekte.

## 4) Statusy a odporúčaná interpretácia

Test by mal vždy vypísať riadok:

```
Status: <value>
```

Odporúčané hodnoty:

- `pass`: bez nálezu
- `warn`: potenciálny problém / odporúčanie
- `fail`: zistený problém
- `critical`: kritický problém

Framework v aktuálnej verzii ukladajúci výsledky do JSON súboru rozlišuje primárne:

- `success`: skript dobehol bez chyby
- `error`: skript spadol (napr. `set -e` + príkaz vrátil nenulový exit)

Preto je vhodné:

- **neukončiť test chybou**, ak ide o očakávaný stav (napr. chýbajúci nástroj),
  ale vrátiť `Status: warn`/`fail` a vypísať vysvetlenie do findings.

## 5) Práca s parametrami (`TEST_PARAMS`)

Vždy používaj bezpečné defaulty:

```bash
foo="$(jq -r '.foo // "default"' <<<"${TEST_PARAMS:-{}}")"
enabled="$(jq -r '.enabled // true' <<<"${TEST_PARAMS:-{}}")"
```

Pre číselné parametre:

```bash
max="$(jq -r '.max // 10' <<<"${TEST_PARAMS:-{}}")"
```

## 6) Praktické tipy (robustnosť)

- **Kontroluj dostupnosť príkazov**:

```bash
if ! command -v ss >/dev/null 2>&1; then
  status="warn"
  findings+=("WARN: command 'ss' not found (install iproute2)")
fi
```

- **Neparsuj zbytočne „ľudské“ výstupy**. Ak existuje strojový formát, použi ho.
- **Timeouty**: pri potenciálne pomalých príkazoch používaj `timeout` (ak je dostupný).
- **Root oprávnenia**: ak niečo vyžaduje root, radšej to explicitne uveď vo findings
  než nechať test spadnúť.

## 7) Overenie testu

Spusti celý audit:

```bash
./main.sh
```

Alebo dočasne vypni ostatné testy (`enabled: false`) a nechaj zapnutý len nový test.

## 8) Ukážka „reálneho“ testu v tomto projekte

Ako referenciu si pozri existujúce skripty v `tests/`, napríklad:

- `tests/firewallCheck.sh`
- `tests/securityUpdatesCheck.sh`
- `tests/sshConfigCheck.sh`

