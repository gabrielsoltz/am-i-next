#!/usr/bin/env bash
# install-schedule.sh — Install/uninstall a scheduled am-i-next scan.
#
# macOS  → ~/Library/LaunchAgents/com.gabrielsoltz.am-i-next.plist
# Linux  → ~/.config/systemd/user/am-i-next.{service,timer}
#
# Reports land in an OS-native state directory (~/Library/Application Support
# on macOS, ~/.local/state on Linux), chmod 700, NEVER inside iCloud/Dropbox.
# Notification fires after every run (findings or clean), count-only.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AM_I_NEXT="${SCRIPT_DIR}/am-i-next.sh"
LABEL="com.gabrielsoltz.am-i-next"

FREQUENCY="daily"     # daily | weekly
TIME_HM="03:17"       # HH:MM, randomized off-hours default
REPORT_DIR=""         # picked by detect_os if not set via --report-dir
RETAIN=30
FORCE=false

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

info()    { echo -e "${BLUE}[*]${NC} $*"; }
ok()      { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[-]${NC} $*" >&2; }
section() { echo -e "\n${BOLD}${CYAN}==> $*${NC}"; }
die()     { err "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") <command> [options]

Commands:
  install     Install the scheduled scan for the current user
  uninstall   Remove the scheduled scan
  status      Show whether a scheduled scan is installed + next run

Options (install):
  --frequency daily|weekly   How often to run (default: daily)
  --time HH:MM               Local time to run (default: 03:17)
  --report-dir <dir>         Where to store reports (default: OS-native)
  --retain N                 Keep N most recent reports (default: 30)
  --force                    Overwrite an existing scheduled scan

Examples:
  $(basename "$0") install
  $(basename "$0") install --frequency weekly --time 04:30
  $(basename "$0") install --report-dir ~/scan-reports --retain 90 --force
  $(basename "$0") status
  $(basename "$0") uninstall
EOF
}

# ---------------------------------------------------------------------------
# Safety + OS detection
# ---------------------------------------------------------------------------

require_not_root() {
    if [[ "$(id -u)" -eq 0 ]]; then
        die "Refusing to run as root — schedule per-user, never as root."
    fi
}

detect_os() {
    case "$(uname -s)" in
        Darwin)
            OS_TYPE="macos"
            DEFAULT_REPORT_DIR="${HOME}/Library/Application Support/am-i-next"
            UNIT_PATH="${HOME}/Library/LaunchAgents/${LABEL}.plist"
            ;;
        Linux)
            OS_TYPE="linux"
            DEFAULT_REPORT_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/am-i-next"
            SYSTEMD_DIR="${HOME}/.config/systemd/user"
            SERVICE_PATH="${SYSTEMD_DIR}/am-i-next.service"
            TIMER_PATH="${SYSTEMD_DIR}/am-i-next.timer"
            ;;
        *)
            die "Unsupported OS: $(uname -s)"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Arg parsing
# ---------------------------------------------------------------------------

parse_install_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --frequency)   FREQUENCY="$2"; shift 2 ;;
            --time)        TIME_HM="$2"; shift 2 ;;
            --report-dir)  REPORT_DIR="$2"; shift 2 ;;
            --retain)      RETAIN="$2"; shift 2 ;;
            --force)       FORCE=true; shift ;;
            *) die "Unknown option: $1. See --help." ;;
        esac
    done

    [[ "${FREQUENCY}" =~ ^(daily|weekly)$ ]] \
        || die "--frequency must be 'daily' or 'weekly' (got: ${FREQUENCY})"
    [[ "${TIME_HM}" =~ ^([0-1][0-9]|2[0-3]):[0-5][0-9]$ ]] \
        || die "--time must be HH:MM in 24h format (got: ${TIME_HM})"
    [[ "${RETAIN}" =~ ^[0-9]+$ ]] \
        || die "--retain must be an integer (got: ${RETAIN})"

    REPORT_DIR="${REPORT_DIR:-${DEFAULT_REPORT_DIR}}"
    TIME_HOUR="${TIME_HM%:*}"
    TIME_MIN="${TIME_HM#*:}"
    TIME_HOUR="${TIME_HOUR#0}"   # strip leading zero for arithmetic-friendly
    TIME_MIN="${TIME_MIN#0}"
    : "${TIME_HOUR:=0}"
    : "${TIME_MIN:=0}"
}

# ---------------------------------------------------------------------------
# Runtime-dep detection
#
# Scheduled contexts (launchd, systemd --user) get a minimal PATH that does
# not include Homebrew (/opt/homebrew/bin on Apple Silicon, /usr/local/bin on
# Intel) or anything else outside /usr/bin:/bin:/usr/sbin:/sbin. We refuse to
# install if trufflehog/jq aren't reachable interactively, then bake their
# directories into the unit's PATH so the scan can find them at fire time.
# ---------------------------------------------------------------------------

check_runtime_deps() {
    command -v trufflehog &>/dev/null || die "trufflehog not found in PATH — install it first (e.g. 'brew install trufflehog')."
    command -v jq         &>/dev/null || die "jq not found in PATH — install it first (e.g. 'brew install jq')."
    TH_BIN_PATH="$(command -v trufflehog)"
    JQ_BIN_PATH="$(command -v jq)"
}

# Build a PATH string suitable for the scheduled job. Puts the directories
# that actually hold trufflehog/jq first, then a sensible default set so
# other helpers (osascript, notify-send, mkdir, ln, env, etc.) still work.
build_unit_path() {
    local th_dir jq_dir
    th_dir="$(dirname "${TH_BIN_PATH}")"
    jq_dir="$(dirname "${JQ_BIN_PATH}")"
    local -a parts=()
    parts+=("${th_dir}")
    [[ "${jq_dir}" != "${th_dir}" ]] && parts+=("${jq_dir}")
    parts+=("/opt/homebrew/bin" "/opt/homebrew/sbin" "/usr/local/bin" "/usr/local/sbin" "/usr/bin" "/bin" "/usr/sbin" "/sbin")
    # Deduplicate while preserving order.
    local seen="" out="" p
    for p in "${parts[@]}"; do
        case ":${seen}:" in *":${p}:"*) ;; *) seen="${seen:+${seen}:}${p}"; out="${out:+${out}:}${p}";; esac
    done
    UNIT_PATH_ENV="${out}"
}

# ---------------------------------------------------------------------------
# macOS: launchd plist generation
# ---------------------------------------------------------------------------

write_plist_macos() {
    local interval_block
    if [[ "${FREQUENCY}" == "daily" ]]; then
        interval_block=$(cat <<EOF
    <key>StartCalendarInterval</key>
    <dict>
      <key>Hour</key><integer>${TIME_HOUR}</integer>
      <key>Minute</key><integer>${TIME_MIN}</integer>
    </dict>
EOF
)
    else
        # Weekly: Sunday (Weekday=0)
        interval_block=$(cat <<EOF
    <key>StartCalendarInterval</key>
    <dict>
      <key>Weekday</key><integer>0</integer>
      <key>Hour</key><integer>${TIME_HOUR}</integer>
      <key>Minute</key><integer>${TIME_MIN}</integer>
    </dict>
EOF
)
    fi

    cat > "${UNIT_PATH}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
      <string>/bin/bash</string>
      <string>-c</string>
      <string>"\$1" --report-dir "\$2" --retain "\$3" --notify --no-banner; rc=\$?; if [ "\$rc" -ne 0 ]; then /usr/bin/osascript -e "display notification \"Scheduled scan failed (exit \$rc). See \$2/launchd.stderr.log\" with title \"am-i-next\""; fi; exit \$rc</string>
      <string>am-i-next-runner</string>
      <string>${AM_I_NEXT}</string>
      <string>${REPORT_DIR}</string>
      <string>${RETAIN}</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
      <key>PATH</key>
      <string>${UNIT_PATH_ENV}</string>
    </dict>
${interval_block}
    <key>RunAtLoad</key><false/>
    <key>StandardOutPath</key><string>${REPORT_DIR}/launchd.stdout.log</string>
    <key>StandardErrorPath</key><string>${REPORT_DIR}/launchd.stderr.log</string>
</dict>
</plist>
EOF
    chmod 600 "${UNIT_PATH}"
}

# ---------------------------------------------------------------------------
# Linux: systemd user timer + service generation
# ---------------------------------------------------------------------------

write_units_linux() {
    local oncalendar
    if [[ "${FREQUENCY}" == "daily" ]]; then
        oncalendar="*-*-* ${TIME_HM}:00"
    else
        oncalendar="Sun *-*-* ${TIME_HM}:00"
    fi

    cat > "${SERVICE_PATH}" <<EOF
[Unit]
Description=am-i-next scheduled credential exposure scan

[Service]
Type=oneshot
Environment=PATH=${UNIT_PATH_ENV}
StandardOutput=append:${REPORT_DIR}/systemd.stdout.log
StandardError=append:${REPORT_DIR}/systemd.stderr.log
ExecStart=/bin/bash -c '"\$1" --report-dir "\$2" --retain "\$3" --notify --no-banner; rc=\$?; if [ "\$rc" -ne 0 ]; then command -v notify-send >/dev/null && notify-send "am-i-next" "Scheduled scan failed (exit \$rc). See \$2/systemd.stderr.log"; fi; exit \$rc' am-i-next-runner ${AM_I_NEXT} ${REPORT_DIR} ${RETAIN}
EOF

    cat > "${TIMER_PATH}" <<EOF
[Unit]
Description=Run am-i-next on a schedule

[Timer]
OnCalendar=${oncalendar}
Persistent=true
Unit=am-i-next.service

[Install]
WantedBy=timers.target
EOF

    chmod 600 "${SERVICE_PATH}" "${TIMER_PATH}"
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

cmd_install() {
    parse_install_args "$@"
    check_runtime_deps
    build_unit_path

    section "Installing scheduled scan"
    info "OS         : ${OS_TYPE}"
    info "Frequency  : ${FREQUENCY} at ${TIME_HM}"
    info "Report dir : ${REPORT_DIR}"
    info "Retain     : ${RETAIN}"
    info "Script     : ${AM_I_NEXT}"
    info "trufflehog : ${TH_BIN_PATH}"
    info "jq         : ${JQ_BIN_PATH}"
    info "Unit PATH  : ${UNIT_PATH_ENV}"

    [[ -x "${AM_I_NEXT}" ]] || die "am-i-next.sh not found or not executable: ${AM_I_NEXT}"

    # Warn if report dir is inside a typical sync root.
    for sync_root in "$HOME/Library/Mobile Documents" "$HOME/Dropbox" "$HOME/OneDrive" "$HOME/Google Drive"; do
        if [[ "${REPORT_DIR}" == "${sync_root}"* ]]; then
            warn "Report dir is inside ${sync_root} — reports may be synced to the cloud!"
        fi
    done

    mkdir -p "${REPORT_DIR}"
    chmod 700 "${REPORT_DIR}"

    case "${OS_TYPE}" in
        macos)
            if [[ -e "${UNIT_PATH}" && "${FORCE}" != true ]]; then
                die "${UNIT_PATH} already exists. Run '$(basename "$0") uninstall' first, or pass --force to overwrite in place."
            fi
            mkdir -p "$(dirname "${UNIT_PATH}")"
            write_plist_macos
            launchctl unload "${UNIT_PATH}" 2>/dev/null || true
            launchctl load "${UNIT_PATH}" || die "launchctl load failed"
            ok "Loaded: ${UNIT_PATH}"
            ;;
        linux)
            if [[ ( -e "${SERVICE_PATH}" || -e "${TIMER_PATH}" ) && "${FORCE}" != true ]]; then
                die "Existing service/timer in ${SYSTEMD_DIR}. Run '$(basename "$0") uninstall' first, or pass --force to overwrite in place."
            fi
            mkdir -p "${SYSTEMD_DIR}"
            write_units_linux
            systemctl --user daemon-reload
            systemctl --user enable --now am-i-next.timer || die "systemctl enable failed"
            ok "Enabled: ${TIMER_PATH}"
            ;;
    esac

    cmd_status
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

cmd_uninstall() {
    section "Uninstalling scheduled scan"
    case "${OS_TYPE}" in
        macos)
            if [[ -e "${UNIT_PATH}" ]]; then
                launchctl unload "${UNIT_PATH}" 2>/dev/null || true
                rm -f "${UNIT_PATH}"
                ok "Removed: ${UNIT_PATH}"
            else
                info "No scheduled scan installed."
            fi
            ;;
        linux)
            systemctl --user disable --now am-i-next.timer 2>/dev/null || true
            rm -f "${SERVICE_PATH}" "${TIMER_PATH}"
            systemctl --user daemon-reload 2>/dev/null || true
            ok "Removed: ${SERVICE_PATH} and ${TIMER_PATH}"
            ;;
    esac
    info "(Report directory left intact: ${DEFAULT_REPORT_DIR})"
}

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

cmd_status() {
    section "Status"
    case "${OS_TYPE}" in
        macos)
            if [[ -e "${UNIT_PATH}" ]]; then
                ok "Installed: ${UNIT_PATH}"
                launchctl list "${LABEL}" 2>/dev/null \
                    | grep -E '"(PID|LastExitStatus|Label)"' || true
            else
                info "Not installed."
            fi
            ;;
        linux)
            if [[ -e "${TIMER_PATH}" ]]; then
                ok "Installed: ${TIMER_PATH}"
                systemctl --user list-timers am-i-next.timer --no-pager 2>/dev/null || true
            else
                info "Not installed."
            fi
            ;;
    esac

    if [[ -d "${REPORT_DIR:-$DEFAULT_REPORT_DIR}" ]]; then
        echo ""
        info "Report directory: ${REPORT_DIR:-$DEFAULT_REPORT_DIR}"
        ls -1t "${REPORT_DIR:-$DEFAULT_REPORT_DIR}"/scan-*.log 2>/dev/null | head -5 \
            | sed 's/^/    /' || true
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    [[ $# -eq 0 ]] && { usage; exit 0; }

    local cmd="$1"; shift
    case "${cmd}" in
        -h|--help|help) usage; exit 0 ;;
    esac

    require_not_root
    detect_os

    case "${cmd}" in
        install)   cmd_install "$@" ;;
        uninstall) cmd_uninstall ;;
        status)    cmd_status ;;
        *) die "Unknown command: ${cmd}. See --help." ;;
    esac
}

main "$@"
