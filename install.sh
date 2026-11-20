#!/usr/bin/env bash
# Install script for tiny-ldap
# Usage: ./install.sh [--pipx|--pip|--dev|--check|--remote]
# Remote one-liner: curl -sSL https://raw.githubusercontent.com/0xClumzzy/tiny/main/install.sh | bash

set -euo pipefail

# === Configuration (update these for your repo) ===
GITHUB_REPO="0xClumzzy/tiny"          # Change to your GitHub user/repo
GITHUB_BRANCH="main"                   # Branch to install from
PACKAGE_NAME="tiny"
MIN_PYTHON="3.9"
# ===================================================

# Detect if running from pipe (curl | bash) vs file
if [[ -n "${BASH_SOURCE[0]:-}" && "${BASH_SOURCE[0]}" != "${0}" ]]; then
    # Sourced or piped - detect remote execution
    PROJECT_DIR=""
    IS_REMOTE=1
elif [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd 2>/dev/null || echo "")"
    IS_REMOTE=0
else
    # Running via pipe (curl | bash) - no BASH_SOURCE
    PROJECT_DIR=""
    IS_REMOTE=1
fi

color_green="\033[0;32m"
color_yellow="\033[1;33m"
color_red="\033[0;31m"
color_reset="\033[0m"

log_info()  { echo -e "${color_green}[+]${color_reset} $*"; }
log_warn()  { echo -e "${color_yellow}[!]${color_reset} $*"; }
log_error() { echo -e "${color_red}[x]${color_reset} $*"; }

check_python() {
    if ! command -v python3 &>/dev/null; then
        log_error "python3 not found. Please install Python ${MIN_PYTHON}+"
        return 1
    fi
    local version
    version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"; then
        log_error "Python ${version} found, but ${MIN_PYTHON}+ is required"
        return 1
    fi
    log_info "Python ${version} OK"
}

install_pipx() {
    local src="${1:-${PROJECT_DIR}}"
    log_info "Installing with pipx (recommended)..."
    if ! command -v pipx &>/dev/null; then
        log_warn "pipx not found. Install it first: https://pipx.pypa.io/installation/"
        log_warn "Falling back to pip install --user"
        install_pip_user "$src"
        return
    fi
    pipx install --editable "$src"
    log_info "Installed via pipx. Run 'tiny --help' to verify."
}

install_pip_user() {
    local src="${1:-${PROJECT_DIR}}"
    log_info "Installing with pip install --user..."
    pip install --user -e "$src"
    log_info "Installed via pip. Ensure ~/.local/bin is in your PATH."
    log_info "Run 'tiny --help' to verify."
}

install_dev() {
    local src="${1:-${PROJECT_DIR}}"
    log_info "Installing in development mode (editable)..."
    pip install -e "$src[dev]" 2>/dev/null || pip install -e "$src"
    log_info "Development install complete. Run 'tiny --help' to verify."
}

install_remote() {
    local repo_url="https://github.com/${GITHUB_REPO}.git"
    local tmpdir
    tmpdir=$(mktemp -d -t tiny-install-XXXXXX)
    log_info "Cloning ${GITHUB_REPO}@${GITHUB_BRANCH} to ${tmpdir}..."
    if ! git clone --depth 1 --branch "${GITHUB_BRANCH}" "${repo_url}" "${tmpdir}" 2>/dev/null; then
        log_error "Failed to clone repository. Check GITHUB_REPO/GITHUB_BRANCH in script."
        rm -rf "${tmpdir}"
        return 1
    fi
    log_info "Installing from cloned source..."
    case "${REMOTE_MODE:-pipx}" in
        pipx)      install_pipx "${tmpdir}" ;;
        pip)       install_pip_user "${tmpdir}" ;;
        dev)       install_dev "${tmpdir}" ;;
    esac
    rm -rf "${tmpdir}"
}

run_check() {
    log_info "Verifying installation..."
    if command -v tiny &>/dev/null; then
        tiny --version
        log_info "tiny is available in PATH"
    elif python3 -m tiny --version 2>/dev/null; then
        log_info "tiny runs via 'python3 -m tiny' (not in PATH)"
    else
        log_error "tiny not found. Installation may have failed."
        return 1
    fi
}

usage() {
    cat <<EOF
Usage: $0 [OPTION]

Install tiny-ldap LDAP triage tool.

Options:
  --pipx       Install with pipx (default, recommended)
  --pip        Install with pip install --user
  --dev        Install in development mode with dev dependencies
  --remote     Install from GitHub (${GITHUB_REPO}@${GITHUB_BRANCH})
  --check      Only verify an existing installation
  --help       Show this help

Environment (for --remote):
  REMOTE_MODE  Installation method for remote: pipx (default), pip, dev

Examples:
  $0                      # Install local with pipx
  $0 --pip                # Install local with pip
  $0 --dev                # Local development install
  $0 --remote             # Install from GitHub via pipx
  $0 --remote --pip       # Install from GitHub via pip
  REMOTE_MODE=dev $0 --remote  # Install from GitHub in dev mode
  $0 --check              # Verify installation

One-liner (remote install without cloning):
  curl -sSL https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}/install.sh | bash
  curl -sSL https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}/install.sh | bash -s -- --pip
EOF
}

main() {
    local mode="pipx"
    case "${1:-}" in
        --pipx)    mode="pipx" ;;
        --pip)     mode="pip" ;;
        --dev)     mode="dev" ;;
        --remote)  mode="remote" ;;
        --check)   mode="check" ;;
        --help|-h) usage; exit 0 ;;
        "")        mode="pipx" ;;
        *)         log_error "Unknown option: $1"; usage; exit 1 ;;
    esac

    # Auto-detect remote execution (curl | bash)
    if [[ "${IS_REMOTE}" -eq 1 && "${mode}" == "pipx" ]]; then
        mode="remote"
    fi

    check_python || exit 1

    case "${mode}" in
        pipx)      install_pipx ;;
        pip)       install_pip_user ;;
        dev)       install_dev ;;
        remote)    install_remote ;;
        check)     run_check ;;
    esac

    if [[ "${mode}" != "check" ]]; then
        run_check
    fi
}

main "$@"
