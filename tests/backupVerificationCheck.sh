#!/usr/bin/env bash
set -euo pipefail

MAX_BACKUP_AGE_DAYS="${MAX_BACKUP_AGE_DAYS:-7}"
REQUIRE_CRON="${REQUIRE_CRON:-1}"

json_escape() {
    printf '%s' "$1" \
        | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/g' \
        | tr -d '\n' \
        | sed 's/\\n$//'
}

FINDINGS=""
FINDING_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
INSTALLED_TOOLS=""
RECENT_TOOLS=""
OLD_TOOLS=""
UNVERIFIABLE_TOOLS=""

add_finding() {
    local msg="$1"
    if [ -z "$FINDINGS" ]; then
        FINDINGS="\"$(json_escape "$msg")\""
    else
        FINDINGS="${FINDINGS}, \"$(json_escape "$msg")\""
    fi
    FINDING_COUNT=$((FINDING_COUNT + 1))
    case "$msg" in
        FAIL*) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        WARNING*) WARN_COUNT=$((WARN_COUNT + 1)) ;;
    esac
}

append_list() {
    # $1=varname, $2=value (quoted string pre JSON)
    local varname="$1" val="$2"
    local current
    current=$(eval echo "\$$varname")
    if [ -z "$current" ]; then
        eval "${varname}=\"\\\"${val}\\\"\""
    else
        eval "${varname}=\"${current}, \\\"${val}\\\"\""
    fi
}

is_installed() {
    command -v "$1" &>/dev/null
}

threshold_timestamp() {
    echo $(( $(date +%s) - MAX_BACKUP_AGE_DAYS * 86400 ))
}

last_backup_timestamp_from_log() {
    local log_path="$1"
    local success_pattern="$2"

    local actual_path="$log_path"
    if [ -d "$log_path" ]; then
        actual_path=$(find "$log_path" -maxdepth 1 -type f \
                      | xargs ls -t 2>/dev/null | head -1)
        [ -z "$actual_path" ] && return
    fi

    [ ! -f "$actual_path" ] && return

    local last_success_line
    last_success_line=$(grep -iE "$success_pattern" "$actual_path" 2>/dev/null | tail -1)
    [ -z "$last_success_line" ] && return

    #YYYY-MM-DD
    local date_str
    date_str=$(echo "$last_success_line" \
               | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1)

    if [ -n "$date_str" ]; then
        date -d "$date_str" +%s 2>/dev/null && return
    fi

    # Fallback: "Mon DD HH:MM:SS"
    date_str=$(echo "$last_success_line" \
               | grep -oE '[A-Z][a-z]{2}[[:space:]]+[0-9]{1,2}[[:space:]]+[0-9]{2}:[0-9]{2}' \
               | head -1)
    if [ -n "$date_str" ]; then
        local year
        year=$(date +%Y)
        date -d "${year} ${date_str}" +%s 2>/dev/null && return
    fi

    stat -c %Y "$actual_path" 2>/dev/null || true
}

has_cron_entry() {
    local tool="$1"
    local cron_paths=("/etc/crontab" "/etc/cron.d" "/etc/cron.daily" \
                      "/etc/cron.weekly" "/var/spool/cron/crontabs")

    for cpath in "${cron_paths[@]}"; do
        if [ -d "$cpath" ]; then
            if grep -rl "$tool" "$cpath" &>/dev/null 2>&1; then
                return 0
            fi
        elif [ -f "$cpath" ]; then
            if grep -q "$tool" "$cpath" 2>/dev/null; then
                return 0
            fi
        fi
    done
    return 1
}

check_tool() {
    local tool="$1"
    local log_paths="$2"      # pipe-separated
    local success_pattern="$3"

    is_installed "$tool" || return

    append_list INSTALLED_TOOLS "$tool"
    add_finding "INFO: Zálohovací nástroj nájdený: ${tool}"

    local threshold
    threshold=$(threshold_timestamp)
    local last_ts=""
    local log_found=0

    IFS='|' read -ra LOG_ARR <<< "$log_paths"
    for log_path in "${LOG_ARR[@]}"; do
        [ -z "$log_path" ] && continue
        if [ -d "$log_path" ] || [ -f "$log_path" ]; then
            log_found=1
            local ts
            ts=$(last_backup_timestamp_from_log "$log_path" "$success_pattern")
            if [ -n "$ts" ]; then
                if [ -z "$last_ts" ] || [ "$ts" -gt "$last_ts" ]; then
                    last_ts="$ts"
                fi
            fi
        fi
    done

    if [ "$log_found" -eq 0 ]; then
        append_list UNVERIFIABLE_TOOLS "$tool"
        add_finding "WARNING: Nástroj '${tool}' nainštalovaný, ale log nenájdený alebo neprístupný"
    elif [ -z "$last_ts" ]; then
        append_list UNVERIFIABLE_TOOLS "$tool"
        add_finding "WARNING: Nástroj '${tool}' — v logu nebola nájdená úspešná záloha"
    else
        local age_days=$(( ( $(date +%s) - last_ts ) / 86400 ))
        local last_date
        last_date=$(date -d "@${last_ts}" "+%Y-%m-%d %H:%M" 2>/dev/null || echo "neznámy")

        if [ "$last_ts" -ge "$threshold" ]; then
            append_list RECENT_TOOLS "$tool"
            add_finding "OK: '${tool}' — posledná záloha pred ${age_days} dňom/dňami (${last_date})"
        else
            append_list OLD_TOOLS "$tool"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            add_finding "FAIL: '${tool}' — záloha je stará ${age_days} dní (prah: ${MAX_BACKUP_AGE_DAYS} dní, dátum: ${last_date})"
        fi
    fi

    # Cron kontrola
    if [ "$REQUIRE_CRON" = "1" ]; then
        if has_cron_entry "$tool"; then
            add_finding "OK: '${tool}' má cron záznam pre automatické zálohovanie"
        else
            add_finding "WARNING: '${tool}' — cron záznam pre automatické zálohovanie nebol nájdený"
        fi
    fi
}

main() {
    check_tool "rsnapshot" \
        "/var/log/rsnapshot.log|/var/log/rsnapshot" \
        "completed successfully"

    check_tool "borg" \
        "/var/log/borg.log|/var/log/borgbackup.log" \
        "Archive name:|terminating with success"

    check_tool "borgbackup" \
        "/var/log/borg.log|/var/log/borgbackup.log" \
        "Archive name:|terminating with success"

    check_tool "restic" \
        "/var/log/restic.log" \
        "snapshot .* saved|successfully saved"

    check_tool "timeshift" \
        "/var/log/timeshift" \
        "Backup saved successfully"

    check_tool "bacula-fd" \
        "/var/log/bacula/bacula.log" \
        "Backup OK|JobStatus=T"

    local status message recommendation

    if [ -z "$INSTALLED_TOOLS" ]; then
        status="FAIL"
        message="Žiadny zálohovací nástroj nebol nájdený — NIS2 vyžaduje kontinuitu prevádzky"
        recommendation="Nainštalujte zálohovací nástroj (napr. borgbackup alebo restic) a nastavte automatické zálohovanie cez cron."
    elif [ "$FAIL_COUNT" -gt 0 ]; then
        status="FAIL"
        message="Zálohy sú zastarané alebo chýbajúce — prah ${MAX_BACKUP_AGE_DAYS} dní bol prekročený"
        recommendation="Skontrolujte zálohovací plán a spustite zálohu manuálne. Overte logy zálohovacieho nástroja."
    elif [ "$WARN_COUNT" -gt 0 ]; then
        status="WARNING"
        message="Zálohovací nástroj nájdený, ale stav zálohovania sa nepodarilo plne overiť"
        recommendation="Skontrolujte konfiguráciu zálohovacieho nástroja a uistite sa že logy sú dostupné a čitateľné."
    else
        status="OK"
        message="Zálohovanie je aktívne a aktuálne"
        recommendation="Zálohovanie je v poriadku, udržujte pravidelný cyklus."
    fi

    cat <<EOF
{
  "test_name": "Backup Verification Check",
  "status": "${status}",
  "message": "$(json_escape "$message")",
  "max_backup_age_days": ${MAX_BACKUP_AGE_DAYS},
  "installed_tools": [${INSTALLED_TOOLS}],
  "tools_with_recent_backup": [${RECENT_TOOLS}],
  "tools_with_old_backup": [${OLD_TOOLS}],
  "tools_without_verifiable_logs": [${UNVERIFIABLE_TOOLS}],
  "findings": [${FINDINGS}],
  "recommendation": "$(json_escape "$recommendation")"
}
EOF

    case "$status" in
        "OK")      exit 0 ;;
        "WARNING") exit 1 ;;
        *)         exit 2 ;;
    esac
}

main "$@"
