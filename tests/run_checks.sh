#!/usr/bin/env bash
# ============================================================
# run_checks.sh — Enumeration Framework Runner (Bash edition)
#
# Usage:
#   ./run_checks.sh [config_file]
#
# Config file format (bash_config.conf):
#   Each enabled test is one line:
#     <script_name>|<description>|<VAR1=val1> <VAR2=val2> ...
#   Lines starting with # are comments.
#
# Environment variables for all tests:
#   TESTS_DIR        — directory containing test scripts (default: ./tests_bash)
#   SAVE_RESULTS     — write JSON-like summary to file (default: true)
#   OUTPUT_FILE      — results output path (default: ./bash_results.txt)
#   RUN_AS_ROOT      — warn if not running as root (default: true)
# ============================================================

CONFIG_FILE="${1:-bash_config.conf}"
TESTS_DIR="${TESTS_DIR:-./tests_bash}"
SAVE_RESULTS="${SAVE_RESULTS:-true}"
OUTPUT_FILE="${OUTPUT_FILE:-./bash_results.txt}"
RUN_AS_ROOT="${RUN_AS_ROOT:-true}"

# ANSI colours
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

TOTAL=0; PASSED=0; WARNED=0; FAILED=0; ERRORED=0
declare -A RESULTS   # test_name -> status

banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║          Linux Security Enumeration Framework            ║"
    echo "║                   Bash Edition                           ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

check_root() {
    if [[ "$RUN_AS_ROOT" == "true" && "$EUID" -ne 0 ]]; then
        echo -e "${YELLOW}[!] WARNING: Not running as root. Some checks may produce incomplete results.${RESET}"
        echo -e "${YELLOW}    Re-run with: sudo $0 $*${RESET}"
        echo ""
    fi
}

load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${RED}[!] Config file not found: ${CONFIG_FILE}${RESET}"
        exit 1
    fi
    echo -e "${BOLD}[*] Loaded config: ${CONFIG_FILE}${RESET}"
}

run_test() {
    local script="$1"
    local description="$2"
    local params="$3"     # space-separated VAR=val pairs
    local test_name
    test_name=$(basename "$script" .sh)
    local script_path="${TESTS_DIR}/${script}"

    if [[ ! -f "$script_path" ]]; then
        echo -e "${RED}  [!] Script not found: ${script_path}${RESET}"
        RESULTS[$test_name]="missing"
        (( ERRORED++ )); (( TOTAL++ ))
        return
    fi

    chmod +x "$script_path" 2>/dev/null

    echo -e "\n${CYAN}${BOLD}$(printf '═%.0s' {1..60})${RESET}"
    echo -e "${BOLD}  Test : ${test_name}${RESET}"
    echo -e "  Desc : ${description}"
    echo -e "${CYAN}$(printf '─%.0s' {1..60})${RESET}"

    # Run the test in a subshell with params exported as env vars
    local output
    local exit_code
    output=$(
        # Export each VAR=val pair
        for pair in $params; do
            export "$pair"
        done
        bash "$script_path" 2>&1
    )
    exit_code=$?

    echo "$output"

    # Parse status from last "Status: <x>" line in output
    local status
    status=$(echo "$output" | grep -oP '(?<=^Status: )\S+' | tail -1)
    status="${status:-unknown}"

    # Colour-code the status
    case "$status" in
        pass)     echo -e "\n  ${GREEN}${BOLD}► Result: PASS${RESET}" ; (( PASSED++ )) ;;
        warn)     echo -e "\n  ${YELLOW}${BOLD}► Result: WARN${RESET}" ; (( WARNED++ )) ;;
        fail|critical) echo -e "\n  ${RED}${BOLD}► Result: ${status^^}${RESET}" ; (( FAILED++ )) ;;
        *)        echo -e "\n  ${YELLOW}${BOLD}► Result: ${status^^}${RESET}" ; (( ERRORED++ )) ;;
    esac

    RESULTS[$test_name]="$status"
    (( TOTAL++ ))

    # Append to output file
    if [[ "$SAVE_RESULTS" == "true" ]]; then
        {
            echo "=== ${test_name} === $(date -Iseconds)"
            echo "Description: ${description}"
            echo "Status: ${status}"
            echo "$output"
            echo ""
        } >> "$OUTPUT_FILE"
    fi
}

print_summary() {
    echo -e "\n${CYAN}${BOLD}$(printf '═%.0s' {1..60})${RESET}"
    echo -e "${BOLD}  ENUMERATION SUMMARY${RESET}"
    echo -e "${CYAN}$(printf '─%.0s' {1..60})${RESET}"
    echo -e "  Total tests run : ${TOTAL}"
    echo -e "  ${GREEN}Passed          : ${PASSED}${RESET}"
    echo -e "  ${YELLOW}Warnings        : ${WARNED}${RESET}"
    echo -e "  ${RED}Failed          : ${FAILED}${RESET}"
    echo -e "  Errors/Missing  : ${ERRORED}"
    echo -e "${CYAN}$(printf '─%.0s' {1..60})${RESET}"
    echo -e "  Per-test results:"
    for name in "${!RESULTS[@]}"; do
        local st="${RESULTS[$name]}"
        case "$st" in
            pass)     echo -e "    ${GREEN}✔ ${name}: ${st}${RESET}" ;;
            warn)     echo -e "    ${YELLOW}⚠ ${name}: ${st}${RESET}" ;;
            fail|critical) echo -e "    ${RED}✘ ${name}: ${st}${RESET}" ;;
            *)        echo -e "    ? ${name}: ${st}" ;;
        esac
    done
    echo -e "${CYAN}${BOLD}$(printf '═%.0s' {1..60})${RESET}"

    if [[ "$SAVE_RESULTS" == "true" ]]; then
        echo -e "\n  ${BOLD}Results saved to: ${OUTPUT_FILE}${RESET}"
    fi
}

# ---------- main ----------
banner
check_root "$@"
load_config

# Initialise output file
if [[ "$SAVE_RESULTS" == "true" ]]; then
    {
        echo "# Bash Security Enumeration Results"
        echo "# Generated: $(date)"
        echo "# Host: $(hostname)"
        echo "# Kernel: $(uname -r)"
        echo ""
    } > "$OUTPUT_FILE"
fi

echo -e "${BOLD}[*] Starting enumeration from ${CONFIG_FILE}${RESET}"

# Read config — skip comments and blank lines
while IFS='|' read -r script description params; do
    [[ -z "$script" || "$script" =~ ^[[:space:]]*# ]] && continue
    script="${script// /}"         # trim whitespace
    description="${description## }"; description="${description%% }"
    run_test "$script" "$description" "$params"
done < "$CONFIG_FILE"

print_summary

echo -e "\n${GREEN}${BOLD}Enumeration complete!${RESET}\n"
