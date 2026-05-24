#!/usr/bin/env bash

set -euo pipefail

SUSPICIOUS_DIRS="${SUSPICIOUS_DIRS:-/tmp /dev/shm /var/tmp /run/shm}"

json_escape() {
    printf '%s' "$1" \
        | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/g' \
        | tr -d '\n' \
        | sed 's/\\n$//'
}

FINDINGS=""
HIDDEN_PIDS=""
DELETED_PROCS=""
SUSPICIOUS_PATH_PROCS=""
FINDING_COUNT=0
HIDDEN_COUNT=0
DELETED_COUNT=0
SUSPICIOUS_PATH_COUNT=0

add_finding() {
    local msg="$1"
    if [ -z "$FINDINGS" ]; then
        FINDINGS="\"$(json_escape "$msg")\""
    else
        FINDINGS="${FINDINGS}, \"$(json_escape "$msg")\""
    fi
    FINDING_COUNT=$((FINDING_COUNT + 1))
}

add_to_array() {
    # $1=varname_ref $2=json_object
    local varname="$1"
    local obj="$2"
    local current
    current=$(eval echo "\$$varname")
    if [ -z "$current" ]; then
        eval "${varname}=\"${obj}\""
    else
        eval "${varname}=\"${current}, ${obj}\""
    fi
}

check_hidden_pids() {
    local proc_pids
    proc_pids=$(ls /proc | grep -E '^[0-9]+$' | sort -n)

    local ps_pids
    ps_pids=$(ps -e -o pid= | tr -d ' ' | sort -n)

    if [ -z "$proc_pids" ] || [ -z "$ps_pids" ]; then
        add_finding "WARNING: Nepodarilo sa porovnať /proc a ps — kontrola skrytých PID preskočená"
        return
    fi

    while IFS= read -r pid; do
        [ -z "$pid" ] && continue
        [ "$pid" -le 1 ] 2>/dev/null && continue
        [ ! -d "/proc/$pid" ] && continue

        local name
        name=$(cat "/proc/$pid/comm" 2>/dev/null || echo "PID_${pid}")
        add_finding "CRITICAL: PID ${pid} (${name}) viditeľný v /proc ale nie v ps — možný rootkit"
        add_to_array HIDDEN_PIDS "{\"pid\": ${pid}, \"name\": \"$(json_escape "$name")\"}"
        HIDDEN_COUNT=$((HIDDEN_COUNT + 1))
    done < <(comm -23 \
        <(echo "$proc_pids") \
        <(echo "$ps_pids") \
        2>/dev/null || true)
}
check_deleted_exe() {
    for pid_dir in /proc/[0-9]*/exe; do
        local pid
        pid=$(echo "$pid_dir" | grep -oE '[0-9]+')
        [ -z "$pid" ] && continue

        local exe_target
        exe_target=$(readlink "$pid_dir" 2>/dev/null || true)
        [ -z "$exe_target" ] && continue

        if echo "$exe_target" | grep -q "(deleted)"; then
            local name
            name=$(cat "/proc/$pid/comm" 2>/dev/null || echo "PID_${pid}")
            add_finding "CRITICAL: Proces ${name} (PID ${pid}) beží zo zmazanej binárky — možná injektáž"
            add_to_array DELETED_PROCS "{\"pid\": ${pid}, \"name\": \"$(json_escape "$name")\"}"
            DELETED_COUNT=$((DELETED_COUNT + 1))
        fi
    done
}

check_suspicious_paths() {
    for pid_dir in /proc/[0-9]*/exe; do
        local pid
        pid=$(echo "$pid_dir" | grep -oE '[0-9]+')
        [ -z "$pid" ] && continue

        local exe_target
        exe_target=$(readlink "$pid_dir" 2>/dev/null || true)
        [ -z "$exe_target" ] && continue

        local exe_clean
        exe_clean=$(echo "$exe_target" | sed 's/ (deleted)$//')

        for sdir in $SUSPICIOUS_DIRS; do
            if echo "$exe_clean" | grep -q "^${sdir}"; then
                local name
                name=$(cat "/proc/$pid/comm" 2>/dev/null || echo "PID_${pid}")
                add_finding "WARNING: Proces ${name} (PID ${pid}) spustený z podozrivého adresára: ${exe_clean}"
                add_to_array SUSPICIOUS_PATH_PROCS \
                    "{\"pid\": ${pid}, \"name\": \"$(json_escape "$name")\", \"exe\": \"$(json_escape "$exe_clean")\"}"
                SUSPICIOUS_PATH_COUNT=$((SUSPICIOUS_PATH_COUNT + 1))
                break
            fi
        done
    done
}

main() {
    check_hidden_pids
    check_deleted_exe
    check_suspicious_paths

    local status message recommendation

    if [ "$FINDING_COUNT" -eq 0 ]; then
        status="OK"
        message="Žiadne podozrivé procesy nenájdené"
        recommendation="Žiadna akcia nie je potrebná"
    elif [ "$DELETED_COUNT" -gt 0 ] || [ "$HIDDEN_COUNT" -gt 0 ]; then
        status="CRITICAL"
        message="Nájdené kritické anomálie: ${DELETED_COUNT} zmazaných bináriek, ${HIDDEN_COUNT} skrytých PID"
        recommendation="Preskúmajte uvedené procesy manuálne. Skryté PID alebo zmazané binárky môžu indikovať rootkit. Zvážte spustenie rkhunter alebo chkrootkit."
    elif [ "$SUSPICIOUS_PATH_COUNT" -gt 0 ]; then
        status="WARNING"
        message="Nájdených ${SUSPICIOUS_PATH_COUNT} procesov spustených z podozrivých adresárov"
        recommendation="Preskúmajte procesy spustené z /tmp a podobných adresárov. Legitímne procesy by sa tu nemali nachádzať."
    else
        status="WARNING"
        message="Nájdené drobné anomálie pri kontrole procesov"
        recommendation="Preskúmajte nálezy manuálne."
    fi

    cat <<EOF
{
  "test_name": "Suspicious Process Check",
  "status": "${status}",
  "message": "$(json_escape "$message")",
  "hidden_pid_count": ${HIDDEN_COUNT},
  "deleted_exe_count": ${DELETED_COUNT},
  "suspicious_path_count": ${SUSPICIOUS_PATH_COUNT},
  "hidden_pids": [${HIDDEN_PIDS}],
  "deleted_exe_processes": [${DELETED_PROCS}],
  "suspicious_path_processes": [${SUSPICIOUS_PATH_PROCS}],
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
