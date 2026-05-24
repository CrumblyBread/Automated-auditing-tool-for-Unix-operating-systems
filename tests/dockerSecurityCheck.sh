#!/usr/bin/env bash

set -euo pipefail

json_escape() {
    printf '%s' "$1" \
        | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/g' \
        | tr -d '\n' \
        | sed 's/\\n$//'
}

FINDINGS=""
FINDING_COUNT=0
CRITICAL_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
CONTAINERS_CHECKED=0
RUNTIME=""

add_finding() {
    local msg="$1"
    if [ -z "$FINDINGS" ]; then
        FINDINGS="\"$(json_escape "$msg")\""
    else
        FINDINGS="${FINDINGS}, \"$(json_escape "$msg")\""
    fi
    FINDING_COUNT=$((FINDING_COUNT + 1))

    case "$msg" in
        CRITICAL*) CRITICAL_COUNT=$((CRITICAL_COUNT + 1)) ;;
        FAIL*)     FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        WARNING*)  WARN_COUNT=$((WARN_COUNT + 1)) ;;
    esac
}

detect_runtime() {
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        RUNTIME="docker"
        return 0
    elif command -v podman &>/dev/null && podman info &>/dev/null 2>&1; then
        RUNTIME="podman"
        return 0
    fi
    return 1
}

check_daemon_config() {
    local daemon_path="/etc/docker/daemon.json"

    if [ ! -f "$daemon_path" ]; then
        add_finding "WARNING: /etc/docker/daemon.json neexistuje — démon beží s predvolenými nastaveniami"
        return
    fi

    if grep -q '"no-new-privileges"' "$daemon_path" 2>/dev/null; then
        local val
        val=$(grep -o '"no-new-privileges"[[:space:]]*:[[:space:]]*[a-z]*' "$daemon_path" \
              | grep -o '[a-z]*$')
        if [ "$val" = "true" ]; then
            add_finding "OK: daemon.json — no-new-privileges=true"
        else
            add_finding "WARNING: daemon.json — no-new-privileges nie je nastavený na true"
        fi
    else
        add_finding "WARNING: daemon.json neobsahuje 'no-new-privileges' (zabraňuje eskalácii privilégií)"
    fi

    if ! grep -q '"userns-remap"' "$daemon_path" 2>/dev/null; then
        add_finding "WARNING: daemon.json neobsahuje 'userns-remap' (user namespace remapping pre izoláciu UID)"
    fi

    if grep -q '"icc"' "$daemon_path" 2>/dev/null; then
        local icc_val
        icc_val=$(grep -o '"icc"[[:space:]]*:[[:space:]]*[a-z]*' "$daemon_path" \
                  | grep -o '[a-z]*$')
        if [ "$icc_val" = "false" ]; then
            add_finding "OK: daemon.json — icc=false (priama komunikácia medzi kontajnermi zakázaná)"
        fi
    fi
}

check_container() {
    local cid="$1"
    local inspect
    inspect=$($RUNTIME inspect "$cid" 2>/dev/null) || return

    local name
    name=$(echo "$inspect" | grep -o '"Name"[[:space:]]*:[[:space:]]*"[^"]*"' \
           | head -1 | sed 's/.*: *"//;s/"//' | sed 's|^/||')
    [ -z "$name" ] && name="$cid"

    if echo "$inspect" | grep -q '"Privileged"[[:space:]]*:[[:space:]]*true'; then
        add_finding "CRITICAL: Kontajner '${name}' beží v privilegovanom režime — plný prístup k hostiteľskému kernelu"
    fi

    if echo "$inspect" | grep -q '/var/run/docker.sock'; then
        add_finding "CRITICAL: Kontajner '${name}' má pripojený Docker socket — umožňuje úplný únik z kontajnera"
    fi

    if echo "$inspect" | grep -q '"NetworkMode"[[:space:]]*:[[:space:]]*"host"'; then
        add_finding "FAIL: Kontajner '${name}' zdieľa hostiteľský network namespace (NetworkMode=host)"
    fi

    if echo "$inspect" | grep -q '"PidMode"[[:space:]]*:[[:space:]]*"host"'; then
        add_finding "FAIL: Kontajner '${name}' zdieľa hostiteľský PID namespace (PidMode=host)"
    fi

    if echo "$inspect" | grep -q '"IpcMode"[[:space:]]*:[[:space:]]*"host"'; then
        add_finding "FAIL: Kontajner '${name}' zdieľa hostiteľský IPC namespace (IpcMode=host)"
    fi

    local mem
    mem=$(echo "$inspect" | grep -o '"Memory"[[:space:]]*:[[:space:]]*[0-9]*' \
          | head -1 | grep -o '[0-9]*$')
    if [ -z "$mem" ] || [ "$mem" = "0" ]; then
        add_finding "WARNING: Kontajner '${name}' nemá nastavený limit pamäte"
    fi

    local cpu
    cpu=$(echo "$inspect" | grep -o '"CpuQuota"[[:space:]]*:[[:space:]]*[0-9]*' \
          | head -1 | grep -o '[0-9]*$')
    if [ -z "$cpu" ] || [ "$cpu" = "0" ]; then
        add_finding "WARNING: Kontajner '${name}' nemá nastavený limit CPU"
    fi

    if ! echo "$inspect" | grep -q '"ReadonlyRootfs"[[:space:]]*:[[:space:]]*true'; then
        add_finding "INFO: Kontajner '${name}' nemá ReadOnly root filesystem — odporúčané pre produkciu"
    fi

    CONTAINERS_CHECKED=$((CONTAINERS_CHECKED + 1))
}

main() {
    if ! detect_runtime; then
        cat <<EOF
{
  "test_name": "Docker/Container Security Check",
  "status": "OK",
  "message": "Docker ani Podman nie sú na systéme nainštalované — test preskočený",
  "findings": ["INFO: Žiadny kontajnerový runtime nebol nájdený"],
  "recommendation": "Žiadna akcia nie je potrebná"
}
EOF
        exit 0
    fi

    add_finding "INFO: Kontajnerový runtime nájdený: ${RUNTIME}"

    if [ "$RUNTIME" = "docker" ]; then
        check_daemon_config
    fi

    local container_ids
    container_ids=$($RUNTIME ps -q 2>/dev/null || true)

    if [ -z "$container_ids" ]; then
        add_finding "INFO: Žiadne bežiace kontajnery nenájdené"
    else
        local count
        count=$(echo "$container_ids" | wc -l | tr -d ' ')
        add_finding "INFO: Nájdených ${count} bežiacich kontajnerov"

        while IFS= read -r cid; do
            [ -z "$cid" ] && continue
            check_container "$cid"
        done <<< "$container_ids"
    fi

    local status message recommendation

    if [ "$CRITICAL_COUNT" -gt 0 ]; then
        status="CRITICAL"
        message="Kritické bezpečnostné problémy v kontajnerovom prostredí: ${CRITICAL_COUNT} nálezov"
        recommendation="Odstráňte privilegované kontajnery a namontované Docker sockety okamžite. Nastavte limity zdrojov a read-only root filesystem."
    elif [ "$FAIL_COUNT" -gt 0 ]; then
        status="FAIL"
        message="Vážne problémy s izoláciou kontajnerov: ${FAIL_COUNT} nálezov"
        recommendation="Odstráňte zdieľané hostiteľské namespaces. Skontrolujte a doplňte /etc/docker/daemon.json podľa CIS Docker Benchmark."
    elif [ "$WARN_COUNT" -gt 0 ]; then
        status="WARNING"
        message="Odporúčané nastavenia kontajnerov nie sú splnené: ${WARN_COUNT} upozornení"
        recommendation="Doplňte odporúčané nastavenia do daemon.json a nastavte limity zdrojov pre kontajnery."
    else
        status="OK"
        message="Kontajnerové prostredie je nakonfigurované bezpečne"
        recommendation="Žiadna akcia nie je potrebná"
    fi

    cat <<EOF
{
  "test_name": "Docker/Container Security Check",
  "status": "${status}",
  "message": "$(json_escape "$message")",
  "runtime": "${RUNTIME}",
  "containers_checked": ${CONTAINERS_CHECKED},
  "findings": [${FINDINGS}],
  "recommendation": "$(json_escape "$recommendation")"
}
EOF

    case "$status" in
        "OK")                   exit 0 ;;
        "WARNING")              exit 1 ;;
        "FAIL"|"CRITICAL"|*)    exit 2 ;;
    esac
}

main "$@"
