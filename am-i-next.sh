#!/usr/bin/env bash
# am-i-next.sh — Scan your developer environment for secrets that would be
# exposed if you were compromised in a supply-chain or credential-theft attack.
#
# Wraps trufflehog (https://github.com/trufflesecurity/trufflehog) and scans
# the locations attackers commonly target after gaining access to a dev machine.
#
# Usage:
#   ./am-i-next.sh [--config <path>] [--output <file>] [--help]

set -uo pipefail

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.conf"
JSON_OUTPUT_FILE=""   # optional raw trufflehog JSON (--json-output)
REPORT_FILE=""        # human-readable report; auto-named if not set via --report
MANIFEST_CLI=""       # --manifest override; empty = use config/default paths.json
VERBOSE=false
FULL_HOME_CLI=""   # tri-state: empty = use config default, true/false = override
VERIFY_CLI=""      # tri-state: empty = use config default, true/false = override

FINDINGS=0
SCANNED=0
SKIPPED=0
ERRORS=0

START_TS=$(date +%s)

# ---------------------------------------------------------------------------
# Colors (disabled if not a terminal)
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    GREEN='\033[0;32m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m'
else
    RED='' YELLOW='' GREEN='' BLUE='' CYAN='' BOLD='' DIM='' NC=''
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info()    { echo -e "${BLUE}[*]${NC} $*"; }
ok()      { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[-]${NC} $*" >&2; }
section() { echo -e "\n${BOLD}${CYAN}==> $*${NC}"; }
die()     { err "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

banner() {
    cat <<'EOF'

   █████╗ ███╗   ███╗   ██╗   ███╗   ██╗███████╗██╗  ██╗████████╗██████╗
  ██╔══██╗████╗ ████║   ██║   ████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝╚════██╗
  ███████║██╔████╔██║   ██║   ██╔██╗ ██║█████╗   ╚███╔╝    ██║     ▄███╔╝
  ██╔══██║██║╚██╔╝██║   ██║   ██║╚██╗██║██╔══╝   ██╔██╗    ██║     ▀▀══╝
  ██║  ██║██║ ╚═╝ ██║   ██║   ██║ ╚████║███████╗██╔╝ ██╗   ██║     ██╗
  ╚═╝  ╚═╝╚═╝     ╚═╝   ╚═╝   ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝     ╚═╝

EOF
    echo -e "${BOLD}  What If I'm Next?${NC} — Developer credential exposure scanner"
    echo -e "${DIM}  Powered by TruffleHog | github.com/trufflesecurity/trufflehog${NC}"
    echo ""
    echo -e "${YELLOW}  WARNING:${NC} This tool is for personal use on your own machine."
    echo -e "  It surfaces secrets that an attacker would find if they compromised you."
    echo ""
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --config <path>      Path to config file (default: ${CONFIG_FILE})
  --manifest <file>    Path to the scan-location manifest (default: paths.json);
                       point at a fetched copy to scan against the upstream list
  --report <file>      Path for the human-readable report (default:
                       \${REPORT_DIR}/scan-<timestamp>.log — always written)
  --json-output <file> Also write the raw trufflehog JSON stream to a file
  --full-home          Scan all of \$HOME in one pass (slower, more thorough);
                       overrides FULL_HOME_SCAN in the config
  --no-verify          Skip verification — show unverified findings only
                       (verification is on by default; see README)
  --verbose            Show each trufflehog invocation
  --help               Show this help

EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --config)       CONFIG_FILE="$2"; shift 2 ;;
            --manifest)     MANIFEST_CLI="$2"; shift 2 ;;
            --report)       REPORT_FILE="$2"; shift 2 ;;
            --json-output)  JSON_OUTPUT_FILE="$2"; shift 2 ;;
            --full-home)    FULL_HOME_CLI=true; shift ;;
            --no-verify)    VERIFY_CLI=false; shift ;;
            --verbose)      VERBOSE=true; shift ;;
            --help|-h)      usage; exit 0 ;;
            *) die "Unknown option: $1. Run with --help for usage." ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

detect_os() {
    section "Environment detection"

    OS_TYPE="unknown"
    IS_WSL=false

    case "$(uname -s)" in
        Darwin)
            OS_TYPE="macos"
            ARCH="$(uname -m)"
            MACOS_VERSION="$(sw_vers -productVersion 2>/dev/null || echo 'unknown')"
            ok "macOS ${MACOS_VERSION} (${ARCH})"
            ;;
        Linux)
            OS_TYPE="linux"
            DISTRO="$(grep -oP '(?<=^ID=).+' /etc/os-release 2>/dev/null | tr -d '"' || echo 'unknown')"
            if grep -qi microsoft /proc/version 2>/dev/null; then
                IS_WSL=true
                ok "Linux/${DISTRO} running under WSL"
                warn "WSL detected — Windows paths (/mnt/c/Users/...) are not scanned by default"
            else
                ok "Linux/${DISTRO}"
            fi
            ;;
        *)
            warn "Unrecognized OS: $(uname -s) — using common locations only"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------

check_deps() {
    section "Checking dependencies"

    if ! command -v jq &>/dev/null; then
        err "jq not found — required to read the scan manifest (paths.json)"
        echo ""
        echo "  Install options:"
        case "${OS_TYPE}" in
            macos) echo "    brew install jq" ;;
            linux) echo "    apt install jq   # or: dnf install jq" ;;
            *)     echo "    https://jqlang.github.io/jq/download/" ;;
        esac
        echo ""
        die "Cannot continue without jq."
    fi

    if ! command -v "${TRUFFLEHOG_BIN}" &>/dev/null; then
        err "trufflehog not found (looked for: ${TRUFFLEHOG_BIN})"
        echo ""
        echo "  Install options:"
        case "${OS_TYPE}" in
            macos)
                echo "    brew install trufflehog"
                echo "    or: curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
                ;;
            linux)
                echo "    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
                echo "    or: snap install trufflehog (if available)"
                ;;
            *)
                echo "    https://github.com/trufflesecurity/trufflehog/releases"
                ;;
        esac
        echo ""
        die "Cannot continue without trufflehog."
    fi

    TH_VERSION="$("${TRUFFLEHOG_BIN}" --version 2>&1 | head -1 || echo 'unknown')"
    ok "jq found: $(jq --version)"
    ok "trufflehog found: ${TH_VERSION}"
    ok "Config file: ${CONFIG_FILE}"
}

# ---------------------------------------------------------------------------
# Manifest loading — populate scan-location + exclude arrays from paths.json
# ---------------------------------------------------------------------------

load_manifest() {
    local manifest="${MANIFEST_FILE:-${SCRIPT_DIR}/paths.json}"
    [[ -f "${manifest}" ]] || die "Manifest not found: ${manifest}"
    jq empty "${manifest}" 2>/dev/null || die "Manifest is not valid JSON: ${manifest}"

    COMMON_SCAN_LOCATIONS=()
    MACOS_SCAN_LOCATIONS=()
    LINUX_SCAN_LOCATIONS=()
    EXCLUDE_PATTERNS=()

    # while-read (not mapfile) for bash 3.2 compatibility.
    while IFS= read -r p; do
        [[ -n "${p}" ]] && COMMON_SCAN_LOCATIONS+=("${p}")
    done < <(jq -r '.scanLocations.common[]?.path' "${manifest}")

    while IFS= read -r p; do
        [[ -n "${p}" ]] && MACOS_SCAN_LOCATIONS+=("${p}")
    done < <(jq -r '.scanLocations.macos[]?.path' "${manifest}")

    while IFS= read -r p; do
        [[ -n "${p}" ]] && LINUX_SCAN_LOCATIONS+=("${p}")
    done < <(jq -r '.scanLocations.linux[]?.path' "${manifest}")

    while IFS= read -r p; do
        [[ -n "${p}" ]] && EXCLUDE_PATTERNS+=("${p}")
    done < <(jq -r '.excludePatterns[]?' "${manifest}")

    MANIFEST_FILE="${manifest}"
    ok "Manifest loaded: ${manifest}"
}

# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

load_config() {
    [[ -f "${CONFIG_FILE}" ]] || die "Config file not found: ${CONFIG_FILE}"
    # shellcheck source=/dev/null
    source "${CONFIG_FILE}"
    ok "Configuration loaded"
}

# ---------------------------------------------------------------------------
# Build the exclude-paths argument (single temp file trufflehog reads)
# ---------------------------------------------------------------------------

build_exclude_file() {
    EXCLUDE_FILE="$(mktemp /tmp/am-i-next-exclude.XXXXXX)"
    # ${arr[@]+"${arr[@]}"} expands to nothing when the array is empty (safe
    # under set -u, even on bash 3.2) instead of injecting an empty element.
    for pattern in ${EXCLUDE_PATTERNS[@]+"${EXCLUDE_PATTERNS[@]}"}; do
        echo "${pattern}" >> "${EXCLUDE_FILE}"
    done
}

cleanup() {
    [[ -n "${EXCLUDE_FILE:-}" ]] && rm -f "${EXCLUDE_FILE}"
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# Scan a single path
# ---------------------------------------------------------------------------

scan_path() {
    local target="$1"

    # Expand ~ if present
    target="${target/#\~/$HOME}"

    if [[ ! -e "${target}" ]]; then
        ((SKIPPED++)) || true
        [[ "${VERBOSE}" == true ]] && info "Skipping (not found): ${target}"
        return
    fi

    info "Scanning: ${target}"
    ((SCANNED++)) || true

    local args=("filesystem" "${target}" "${TRUFFLEHOG_EXTRA_ARGS[@]}")

    [[ "${VERIFY}" != true ]] && args+=("--no-verification")

    # USER_RESULTS / RESULTS_EFFECTIVE are computed once in main(). If the
    # user didn't pin --results in TRUFFLEHOG_EXTRA_ARGS, inject the derived
    # value here so it shows up on the command line.
    [[ -z "${USER_RESULTS}" ]] && args+=("--results=${RESULTS_EFFECTIVE}")

    if [[ -f "${EXCLUDE_FILE}" && -s "${EXCLUDE_FILE}" ]]; then
        args+=("--exclude-paths=${EXCLUDE_FILE}")
    fi

    [[ "${VERBOSE}" == true ]] && echo "    cmd: ${TRUFFLEHOG_BIN} ${args[*]}"

    local output
    local exit_code=0

    if [[ -n "${JSON_OUTPUT_FILE}" ]]; then
        output="$("${TRUFFLEHOG_BIN}" "${args[@]}" 2>/dev/null | tee -a "${JSON_OUTPUT_FILE}")" || exit_code=$?
    else
        output="$("${TRUFFLEHOG_BIN}" "${args[@]}" 2>/dev/null)" || exit_code=$?
    fi

    # trufflehog exits 183 when secrets are found (v3.x), 0 when clean
    local count=0
    if [[ -n "${output}" ]]; then
        count="$(echo "${output}" | grep -c '"SourceMetadata"' 2>/dev/null || echo 0)"
    fi

    if [[ "${count}" -gt 0 ]]; then
        ((FINDINGS += count)) || true
        warn "${count} finding(s) in: ${target}"
        echo "${output}" | pretty_print_findings
        {
            echo "[${count} FINDING(S)] ${target}"
            echo "${output}" | findings_plain | sed 's/^/    /'
            echo ""
        } >> "${REPORT_FILE}"
    else
        echo "[clean]              ${target}" >> "${REPORT_FILE}"
    fi

    if [[ "${exit_code}" -ne 0 && "${exit_code}" -ne 183 ]]; then
        ((ERRORS++)) || true
        warn "trufflehog exited with code ${exit_code} for: ${target}"
    fi
}

# ---------------------------------------------------------------------------
# Pretty-print JSON findings to the terminal
# ---------------------------------------------------------------------------

pretty_print_findings() {
    if command -v jq &>/dev/null; then
        jq -r '
            (if .Verified == true then "[32mVERIFIED[0m"
             elif (.VerificationError // "") != "" then "[33mUNKNOWN[0m"
             else "[36mUNVERIFIED[0m" end) as $status |
            "  [31m[SECRET][0m [" + $status + "] " +
            (.DetectorName // "unknown") +
            " — " +
            (
                .SourceMetadata.Data
                | to_entries[0].value
                | to_entries
                | map("\(.key)=\(.value)")
                | join(", ")
            )
        ' 2>/dev/null || cat
    else
        grep -o '"DetectorName":"[^"]*"' | sed 's/"DetectorName":"//;s/"//' \
            | while read -r name; do echo -e "  ${RED}[SECRET]${NC} ${name}"; done
    fi
}

# ---------------------------------------------------------------------------
# Plain (no-color) findings, for the report file
# ---------------------------------------------------------------------------

findings_plain() {
    if command -v jq &>/dev/null; then
        jq -r '
            (if .Verified == true then "VERIFIED"
             elif (.VerificationError // "") != "" then "UNKNOWN"
             else "UNVERIFIED" end) as $status |
            "[SECRET] [" + $status + "] " +
            (.DetectorName // "unknown") +
            " — " +
            (
                .SourceMetadata.Data
                | to_entries[0].value
                | to_entries
                | map("\(.key)=\(.value)")
                | join(", ")
            )
        ' 2>/dev/null || cat
    else
        grep -o '"DetectorName":"[^"]*"' | sed 's/"DetectorName":"//;s/"//' \
            | while read -r name; do echo "[SECRET] ${name}"; done
    fi
}

# ---------------------------------------------------------------------------
# Initialize the report file with a header
# ---------------------------------------------------------------------------

init_report() {
    mkdir -p "$(dirname "${REPORT_FILE}")"
    {
        echo "am-i-next scan report"
        echo "====================="
        echo "Date        : $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "Host        : $(hostname)"
        echo "User        : ${USER:-$(whoami)}"
        echo "OS          : ${OS_TYPE}"
        echo "TruffleHog  : ${TH_VERSION}"
        echo "Full-home   : ${FULL_HOME}"
        echo "Verify      : ${VERIFY}"
        echo "Results     : ${RESULTS_EFFECTIVE}"
        echo "Locations   : ${#LOCATIONS[@]}"
        echo ""
        echo "WARNING: this file can contain secret material. Handle with care."
        echo ""
        echo "Per-location results"
        echo "--------------------"
    } > "${REPORT_FILE}"
}

# ---------------------------------------------------------------------------
# Build the location list for the current OS
# ---------------------------------------------------------------------------

collect_locations() {
    LOCATIONS=()

    # Gather the full configured set for this OS first.
    # ${arr[@]+"${arr[@]}"} avoids injecting an empty element when an array is
    # empty (safe under set -u, including bash 3.2).
    local configured=(${COMMON_SCAN_LOCATIONS[@]+"${COMMON_SCAN_LOCATIONS[@]}"})
    case "${OS_TYPE}" in
        macos) configured+=(${MACOS_SCAN_LOCATIONS[@]+"${MACOS_SCAN_LOCATIONS[@]}"}) ;;
        linux) configured+=(${LINUX_SCAN_LOCATIONS[@]+"${LINUX_SCAN_LOCATIONS[@]}"}) ;;
    esac

    if [[ "${FULL_HOME}" == true ]]; then
        # Scan all of $HOME in one pass, then add only the configured paths
        # that live OUTSIDE $HOME (e.g. /tmp, /etc/*) — paths under $HOME would
        # be redundant with the full-home scan.
        LOCATIONS+=("$HOME")
        for loc in "${configured[@]}"; do
            local expanded="${loc/#\~/$HOME}"
            if [[ "${expanded}" != "$HOME" && "${expanded}" != "$HOME"/* ]]; then
                LOCATIONS+=("${loc}")
            fi
        done
        return
    fi

    LOCATIONS=("${configured[@]}")
}

# ---------------------------------------------------------------------------
# Print summary
# ---------------------------------------------------------------------------

print_summary() {
    local end_ts elapsed
    end_ts=$(date +%s)
    elapsed=$((end_ts - START_TS))

    section "Summary"
    echo -e "  Locations scanned : ${SCANNED}"
    echo -e "  Locations skipped : ${SKIPPED} (not found on disk)"
    echo -e "  Scan errors       : ${ERRORS}"
    echo -e "  Elapsed time      : ${elapsed}s"
    echo ""

    if [[ "${FINDINGS}" -gt 0 ]]; then
        echo -e "  ${RED}${BOLD}Total findings: ${FINDINGS}${NC}"
        echo ""
        echo -e "  ${YELLOW}These secrets would be accessible to an attacker who"
        echo -e "  compromises your machine or steals your session tokens.${NC}"
        echo ""
        echo "  Remediation steps to consider:"
        echo "    1. Move all secrets out of files and into a secrets manager (1Password, Vault, etc.)."
        echo "    2. Add 2FA/MFA/FIDO2/Passkeys to any accounts that don't have it yet, especially for email, password managers, cloud providers, and source control."
        echo "    3. Use short-lived credentials instead of long-lived secrets where possible (e.g. cloud provider roles)."
        echo "    4. Remove browser cache and history entries that may contain secrets."
        echo "    5. Remove AI tool history entries that may contain secrets (e.g. ChatGPT, Copilot Labs)."
    else
        echo -e "  ${GREEN}${BOLD}No findings — looking clean!${NC}"
        echo ""
        if [[ "${VERIFY}" == true ]]; then
            echo -e "  ${DIM}Tip: re-run with --no-verify to also see unverified candidates trufflehog couldn't confirm.${NC}"
        fi
    fi
    echo ""

    {
        echo ""
        echo "Summary"
        echo "-------"
        echo "Locations scanned : ${SCANNED}"
        echo "Locations skipped : ${SKIPPED} (not found on disk)"
        echo "Scan errors       : ${ERRORS}"
        echo "Total findings    : ${FINDINGS}"
        echo "Elapsed           : ${elapsed}s"
    } >> "${REPORT_FILE}"

    ok "Report saved → ${REPORT_FILE}"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    banner
    parse_args "$@"
    load_config
    detect_os
    check_deps
    # --manifest wins over the config/default path.
    [[ -n "${MANIFEST_CLI}" ]] && MANIFEST_FILE="${MANIFEST_CLI}"
    load_manifest
    build_exclude_file

    # Resolve full-home mode: CLI flag wins over the config default.
    FULL_HOME="${FULL_HOME_CLI:-${FULL_HOME_SCAN:-false}}"

    # Resolve verification mode: CLI flag wins over the config default.
    VERIFY="${VERIFY_CLI:-${VERIFY:-true}}"

    # Determine the effective --results value (used by scan_path and shown to
    # the user). The user's explicit --results=... in TRUFFLEHOG_EXTRA_ARGS
    # wins; otherwise we derive from VERIFY.
    USER_RESULTS=""
    for arg in ${TRUFFLEHOG_EXTRA_ARGS[@]+"${TRUFFLEHOG_EXTRA_ARGS[@]}"}; do
        if [[ "${arg}" == --results=* ]]; then
            USER_RESULTS="${arg#--results=}"
            break
        fi
    done
    if [[ -n "${USER_RESULTS}" ]]; then
        RESULTS_EFFECTIVE="${USER_RESULTS}"
    elif [[ "${VERIFY}" == true ]]; then
        RESULTS_EFFECTIVE="verified"
    else
        RESULTS_EFFECTIVE="unverified"
    fi

    collect_locations

    # Resolve the report path: --report wins, else REPORT_DIR/scan-<timestamp>.log
    REPORT_FILE="${REPORT_FILE:-${REPORT_DIR:-.}/scan-$(date +%Y-%m-%d-%H%M%S).log}"
    init_report

    section "Scanning options"
    ok "Verify   : ${VERIFY}"
    ok "Results  : ${RESULTS_EFFECTIVE}"
    ok "Report   → ${REPORT_FILE}"
    [[ -n "${JSON_OUTPUT_FILE}" ]] && ok "Raw JSON → ${JSON_OUTPUT_FILE}"

    section "Scanning ${#LOCATIONS[@]} locations"
    if [[ "${FULL_HOME}" == true ]]; then
        warn "Full-home mode: scanning all of \$HOME — this may take a while."
    fi
    echo -e "${DIM}  (non-existent paths are silently skipped)${NC}\n"

    for location in "${LOCATIONS[@]}"; do
        scan_path "${location}"
    done

    print_summary
}

main "$@"
