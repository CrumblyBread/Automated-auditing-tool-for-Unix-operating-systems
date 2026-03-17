#!/usr/bin/env bash
# =============================================================================
# Enumeration Framework - main.sh
# Usage: ./main.sh [config.json]
# =============================================================================

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
CONFIG_PATH="${1:-config.json}"
TESTS_DIR=""
OUTPUT_FILE=""
SAVE_RESULTS=""

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
    for i in $(seq 0 $((count - 1))); do
        local enabled name file path
        enabled=$(jq -r ".tests[$i].enabled // false" "$CONFIG_PATH")
        name=$(jq -r ".tests[$i].name" "$CONFIG_PATH")
        file=$(jq -r ".tests[$i].file" "$CONFIG_PATH")

        if [[ "$enabled" != "true" ]]; then
            echo "Skipping disabled test: $name"
            continue
        fi

        # Convert .py filename to .sh
        local sh_file="${file%.py}.sh"
        path="$TESTS_DIR/$sh_file"

        if [[ ! -f "$path" ]]; then
            echo "Test file not found: $path"
            continue
        fi

        if ! grep -q '^run()' "$path" 2>/dev/null; then
            echo "Test script $sh_file missing 'run()' function"
            continue
        fi

        echo "Loaded test: $name"
        (( loaded++ )) || true
    done

    [[ "$loaded" -gt 0 ]]
}

run_test() {
    local index="$1"
    local name file sh_file path params_json timestamp

    name=$(jq -r ".tests[$index].name" "$CONFIG_PATH")
    file=$(jq -r ".tests[$index].file" "$CONFIG_PATH")
    sh_file="${file%.py}.sh"
    path="$TESTS_DIR/$sh_file"
    params_json=$(jq -c ".tests[$index].parameters // {}" "$CONFIG_PATH")
    timestamp=$(date -Iseconds)

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

    # Source the test script and call run() with params JSON via env var
    local output
    if output=$(TEST_PARAMS="$params_json" bash -c "source '$path'; run" 2>&1); then
        echo "$output"
        RESULTS_STATUS["$name"]="success"
        RESULTS_OUTPUT["$name"]="$output"
    else
        echo "Error executing test $name"
        echo "$output"
        RESULTS_STATUS["$name"]="error"
        RESULTS_OUTPUT["$name"]="$output"
    fi
    RESULTS_TIMESTAMP["$name"]="$timestamp"
}

run_all_tests() {
    local count
    count=$(jq '.tests | length' "$CONFIG_PATH")
    local loaded=0

    for i in $(seq 0 $((count - 1))); do
        local enabled name file sh_file path
        enabled=$(jq -r ".tests[$i].enabled // false" "$CONFIG_PATH")
        name=$(jq -r ".tests[$i].name" "$CONFIG_PATH")
        file=$(jq -r ".tests[$i].file" "$CONFIG_PATH")
        sh_file="${file%.py}.sh"
        path="$TESTS_DIR/$sh_file"

        if [[ "$enabled" != "true" ]]; then continue; fi
        if [[ ! -f "$path" ]]; then continue; fi
        if ! grep -q '^run()' "$path" 2>/dev/null; then continue; fi

        run_test "$i"
        (( loaded++ )) || true
    done

    echo ""
    echo "Starting enumeration with $loaded test(s)"
    print_summary
}

print_summary() {
    printf '\n%s\n' "$(printf '=%.0s' {1..60})"
    echo "ENUMERATION SUMMARY"
    printf '%s\n' "$(printf '=%.0s' {1..60})"

    local total=0 successful=0 failed=0
    for name in "${!RESULTS_STATUS[@]}"; do
        (( total++ )) || true
        if [[ "${RESULTS_STATUS[$name]}" == "success" ]]; then
            (( successful++ )) || true
        else
            (( failed++ )) || true
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
    local first=true

    for name in "${!RESULTS_STATUS[@]}"; do
        [[ "$first" == "true" ]] && first=false || json+=","
        local escaped_output
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

# ── Entry point ───────────────────────────────────────────────────────────────
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

main
