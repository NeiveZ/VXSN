#!/usr/bin/env bash
# VXSN - Vulnerability & Exploit Scanner
# Author: NeiveZ | github.com/NeiveZ/VXSN
 
set -euo pipefail

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
CYAN='\033[96m'; BOLD='\033[1m'; RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"

ok()   { echo -e "  ${GREEN}[+]${RESET} $*"; }
err()  { echo -e "  ${RED}[-]${RESET} $*"; }
info() { echo -e "  ${CYAN}[*]${RESET} $*"; }
warn() { echo -e "  ${YELLOW}[!]${RESET} $*"; }

check_python() {
    command -v "$PYTHON" &>/dev/null || { err "Python 3 not found."; exit 1; }
    PY_VER=$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    "$PYTHON" -c "import sys; exit(0 if sys.version_info >= (3,10) else 1)" 2>/dev/null \
        && ok "Python $PY_VER detected" \
        || warn "Python $PY_VER — VXSN recommends Python 3.10+"
}

create_dirs() {
    mkdir -p "$SCRIPT_DIR/reports"
    ok "Directory structure verified"
}

run_tool() {
    cd "$SCRIPT_DIR"
    exec "$PYTHON" vxsn.py "$@"
}

case "${1:-}" in
    --install|-i)
        echo -e "\n${BOLD}${RED}VXSN Installer${RESET}\n"
        check_python
        create_dirs
        chmod +x "$SCRIPT_DIR/vxsn.py" 2>/dev/null || true
        echo
        ok "Installation complete."
        info "Run with: ${CYAN}./vxsn.sh${RESET}"
        echo
        ;;
    --check)
        check_python
        ;;
    --help|-h)
        echo -e """
${BOLD}${RED}VXSN${RESET} — Vulnerability & Exploit Scanner

${BOLD}Usage:${RESET}
  ./vxsn.sh            Launch interactive shell
  ./vxsn.sh --install  Verify environment
  ./vxsn.sh --check    Check Python version
  ./vxsn.sh --help     Show this help
"""
        ;;
    *)
        check_python
        create_dirs
        run_tool "$@"
        ;;
esac
