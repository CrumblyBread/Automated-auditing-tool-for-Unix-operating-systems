#!/usr/bin/env bash
# =============================================================================
# Enumeration Framework - main.sh (Bash edition)
# Usage: ./main.sh [config.json]
# =============================================================================

set -euo pipefail

CONFIG_PATH="${1:-config.json}"
TESTS_DIR=""
OUTPUT_FILE=""
SAVE_RESULTS="false"

declare -A RESULTS_STATUS
declare -A RESULTS_OUTPUT
declare -A RESULTS_TIMESTAMP

# ── Helpers ───────────────────────────────────────────────────────────────────

require_jq() {
    if ! command -v jq &>/dev/null; then
        echo "ERROR: 'jq' is required but not installed. Install it with: sudo apt install jq" >&2
        exit 1
    fi
}

# config "file" may be name.sh, name.py (→ name.sh), or bare name (→ name.sh)
resolve_test_path() {
    local file="$1"
    local base

    if [[ "$file" == *.sh ]]; then
        base="$file"
    elif [[ "$file" == *.py ]]; then
        base="${file%.py}.sh"
    else
        base="${file}.sh"
    fi

    echo "${TESTS_DIR}/${base}"
}

# Export config parameters as ENV vars: min_kernel_version → MIN_KERNEL_VERSION
export_test_params() {
    local params_json="${1:-{}}"

    if [[ -z "$params_json" || "$params_json" == "null" ]]; then
        return 0
    fi

    local key val val_type env_key
    while IFS= read -r key; do
        [[ -z "$key" ]] && continue
        env_key=$(echo "$key" | tr '[:lower:]' '[:upper:]')
        val_type=$(jq -r --arg k "$key" '.[$k] | type' <<<"$params_json")

        case "$val_type" in
            array)
                val=$(jq -r --arg k "$key" '.[$k] | map(tostring) | join(" ")' <<<"$params_json")
                ;;
            boolean|number)
                val=$(jq -r --arg k "$key" '.[$k] | tostring' <<<"$params_json")
                ;;
            *)
                val=$(jq -r --arg k "$key" '.[$k] | tostring' <<<"$params_json")
                ;;
        esac

        export "${env_key}=${val}"
    done < <(jq -r 'keys[]' <<<"$params_json")
}

load_config() {
    if [[ ! -f "$CONFIG_PATH" ]]; then
        echo "Configuration file not found: $CONFIG_PATH" >&2
        return 1
    fi

    if ! jq empty "$CONFIG_PATH" 2>/dev/null; then
        echo "Error parsing configuration file: $CONFIG_PATH" >&2
        return 1
    fi

    TESTS_DIR=$(jq -r '.tests_directory // "tests"' "$CONFIG_PATH")
    OUTPUT_FILE=$(jq -r '.output_file // "enumeration_results.json"' "$CONFIG_PATH")
    SAVE_RESULTS=$(jq -r '.save_results // false' "$CONFIG_PATH")

    if [[ ! -d "$TESTS_DIR" ]]; then
        echo "Tests directory not found: $TESTS_DIR" >&2
        return 1
    fi

    echo "Configuration loaded from $CONFIG_PATH"
    return 0
}

discover_tests() {
    local count
    count=$(jq '.tests | length' "$CONFIG_PATH")

    if [[ "$count" -eq 0 ]]; then
        echo "No tests defined in configuration" >&2
        return 1
    fi

    local loaded=0
    local i path file enabled name

    for ((i = 0; i < count; i++)); do
        enabled=$(jq -r ".tests[$i].enabled // false" "$CONFIG_PATH")
        name=$(jq -r ".tests[$i].name" "$CONFIG_PATH")
        file=$(jq -r ".tests[$i].file" "$CONFIG_PATH")
        path=$(resolve_test_path "$file")

        if [[ "$enabled" != "true" ]]; then
            echo "Skipping disabled test: $name"
            continue
        fi

        if [[ ! -f "$path" ]]; then
            echo "Test file not found: $path"
            continue
        fi

        if [[ ! -x "$path" ]]; then
            chmod +x "$path" 2>/dev/null || true
        fi

        echo "Loaded test: $name ($path)"
        ((loaded++)) || true
    done

    [[ "$loaded" -gt 0 ]]
}

run_test() {
    local index="$1"
    local name file path params_json timestamp output exit_code

    name=$(jq -r ".tests[$index].name" "$CONFIG_PATH")
    file=$(jq -r ".tests[$index].file" "$CONFIG_PATH")
    path=$(resolve_test_path "$file")
    params_json=$(jq -c ".tests[$index].parameters // {}" "$CONFIG_PATH")
    timestamp=$(date -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')

    printf '\n%s\n' "$(printf '=%.0s' {1..60})"
    echo "Running: $name"
    printf '%s\n' "$(printf '=%.0s' {1..60})"

    if [[ ! -f "$path" ]]; then
        echo "Test file not found: $path"
        RESULTS_STATUS["$name"]="error"
        RESULTS_OUTPUT["$name"]="Test file not found: $path"
        RESULTS_TIMESTAMP["$name"]="$timestamp"
        return
    fi

    set +e
    output=$(
        export_test_params "$params_json"
        bash "$path"
    2>&1)
    exit_code=$?
    set -e

    echo "$output"

    if [[ "$exit_code" -eq 0 ]]; then
        RESULTS_STATUS["$name"]="success"
    else
        RESULTS_STATUS["$name"]="error"
    fi
    RESULTS_OUTPUT["$name"]="$output"
    RESULTS_TIMESTAMP["$name"]="$timestamp"
}

run_all_tests() {
    local count loaded=0
    count=$(jq '.tests | length' "$CONFIG_PATH")

    local i enabled path file name
    for ((i = 0; i < count; i++)); do
        enabled=$(jq -r ".tests[$i].enabled // false" "$CONFIG_PATH")
        [[ "$enabled" != "true" ]] && continue

        file=$(jq -r ".tests[$i].file" "$CONFIG_PATH")
        path=$(resolve_test_path "$file")
        [[ ! -f "$path" ]] && continue

        run_test "$i"
        ((loaded++)) || true
    done

    echo ""
    echo "Finished running $loaded test(s)"
    print_summary
}

print_summary() {
    printf '\n%s\n' "$(printf '=%.0s' {1..60})"
    echo "ENUMERATION SUMMARY"
    printf '%s\n' "$(printf '=%.0s' {1..60})"

    local total=0 successful=0 failed=0 name

    for name in "${!RESULTS_STATUS[@]}"; do
        ((total++)) || true
        if [[ "${RESULTS_STATUS[$name]}" == "success" ]]; then
            ((successful++)) || true
        else
            ((failed++)) || true
        fi
    done

    echo "Total tests run : $total"
    echo "Successful      : $successful"
    echo "Failed          : $failed"

    if [[ "$SAVE_RESULTS" == "true" ]]; then
        save_results
    fi
}

save_results() {
    local json="{"
    local first=true name escaped_output

    for name in "${!RESULTS_STATUS[@]}"; do
        [[ "$first" == "true" ]] && first=false || json+=","
        escaped_output=$(printf '%s' "${RESULTS_OUTPUT[$name]}" | jq -Rs .)
        json+=$(printf '"%s":{"status":"%s","output":%s,"timestamp":"%s"}' \
            "$name" \
            "${RESULTS_STATUS[$name]}" \
            "$escaped_output" \
            "${RESULTS_TIMESTAMP[$name]}")
    done

    json+="}"
    echo "$json" | jq . > "$OUTPUT_FILE"
    echo ""
    echo "Results saved to: $OUTPUT_FILE"
}

main() {
    echo "Start"
    require_jq

    load_config || exit 1

    if ! discover_tests; then
        echo "No tests loaded. Exiting."
        exit 1
    fi

    run_all_tests

    echo ""
    echo "Enumeration complete!"
}

main "$@"
