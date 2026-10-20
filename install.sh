#!/bin/sh
# asset-reachability installer
#
#   curl -fsSL https://raw.githubusercontent.com/d0gban/asset_reachability/main/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --no-deps --prefix "$HOME/.local/bin"
#
# Installs `asset-reachability` and (unless --no-deps) the optional tools that
# unlock the more accurate probe methods: nmap, arping, dig, nc.
#
# Options:
#   --prefix DIR   install directory (default: /usr/local/bin as root/sudo, else ~/.local/bin)
#   --ref REF      git branch/tag/commit to install (default: main; env AR_REF)
#   --no-deps      don't install optional dependencies
#   --uninstall    remove the installed command
#   -h, --help     show this help
#
# Env: AR_REPO (owner/name), AR_REF, AR_SHA256 (pin the expected script checksum)

set -eu

REPO="${AR_REPO:-d0gban/asset_reachability}"
REF="${AR_REF:-main}"
SCRIPT_NAME="asset_reachability.sh"
CMD_NAME="asset-reachability"
PREFIX=""
WITH_DEPS=1
UNINSTALL=0

if [ -t 1 ]; then B=$(printf '\033[1m'); G=$(printf '\033[32m'); Y=$(printf '\033[33m'); R=$(printf '\033[31m'); N=$(printf '\033[0m'); else B=""; G=""; Y=""; R=""; N=""; fi
info() { printf '%s==>%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '%s ok%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%swarn:%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    cat <<USAGE
Usage: install.sh [--prefix DIR] [--ref REF] [--no-deps] [--uninstall]
  --prefix DIR   install dir (default: /usr/local/bin as root/sudo, else ~/.local/bin)
  --ref REF      git branch/tag/commit (default: main)
  --no-deps      skip optional dependency install
  --uninstall    remove the installed command
Env: AR_REPO, AR_REF, AR_SHA256, AR_BASE_URL
USAGE
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case $1 in
        --prefix)    [ $# -ge 2 ] || die "--prefix needs a directory"; PREFIX=$2; shift 2 ;;
        --ref)       [ $# -ge 2 ] || die "--ref needs a value"; REF=$2; shift 2 ;;
        --no-deps)   WITH_DEPS=0; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help)   usage 0 ;;
        *)           die "unknown option: $1 (try --help)" ;;
    esac
done

# --- platform ---------------------------------------------------------------
OS=$(uname -s 2>/dev/null || echo unknown)
case $OS in
    Linux|Darwin) ;;
    *) die "unsupported OS '$OS'. On Windows, run this inside WSL." ;;
esac

# --- privilege helper -------------------------------------------------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if have sudo; then SUDO="sudo"; fi
fi

# --- install dir ------------------------------------------------------------
if [ -z "$PREFIX" ]; then
    if [ "$(id -u)" -eq 0 ] || [ -n "$SUDO" ]; then PREFIX="/usr/local/bin"; else PREFIX="$HOME/.local/bin"; fi
fi
# Need elevated rights only if the prefix isn't writable by us.
PFX_SUDO=""
if [ ! -w "$PREFIX" ] && { [ -d "$PREFIX" ] || ! mkdir -p "$PREFIX" 2>/dev/null; }; then
    [ "$(id -u)" -eq 0 ] || [ -n "$SUDO" ] || die "$PREFIX isn't writable and sudo isn't available. Use --prefix \"\$HOME/.local/bin\"."
    PFX_SUDO="$SUDO"
fi
DEST="$PREFIX/$CMD_NAME"

# --- uninstall --------------------------------------------------------------
if [ "$UNINSTALL" -eq 1 ]; then
    removed=0
    for d in "$PREFIX" /usr/local/bin "$HOME/.local/bin"; do
        if [ -f "$d/$CMD_NAME" ]; then
            if [ -w "$d" ]; then rm -f "$d/$CMD_NAME"; else ${SUDO:+$SUDO} rm -f "$d/$CMD_NAME"; fi
            ok "removed $d/$CMD_NAME"; removed=1
        fi
    done
    [ "$removed" -eq 1 ] || warn "nothing to remove"
    exit 0
fi

# --- dependencies -----------------------------------------------------------
install_deps() {
    missing=""
    have nmap    || missing="$missing nmap"
    have arping  || missing="$missing arping"
    have dig     || missing="$missing dig"
    have nc      || missing="$missing nc"
    have ping    || missing="$missing ping"
    # bash >= 4.4 is mandatory
    bash_ok=0
    if have bash && bash -c '[ "${BASH_VERSINFO[0]}" -gt 4 ] || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -ge 4 ]; }' 2>/dev/null; then bash_ok=1; fi
    [ "$bash_ok" -eq 1 ] || missing="$missing bash"
    have timeout || have gtimeout || missing="$missing timeout"
    [ -n "$missing" ] || { ok "all dependencies present"; return 0; }
    info "installing missing tools:$missing"

    pk=""
    for m in $missing; do
        if have apt-get; then
            case $m in nmap) pk="$pk nmap";; arping) pk="$pk iputils-arping";; dig) pk="$pk dnsutils";;
                       nc) pk="$pk netcat-openbsd";; ping) pk="$pk iputils-ping";; bash) pk="$pk bash";; timeout) pk="$pk coreutils";; esac
        elif have dnf || have yum; then
            case $m in nmap) pk="$pk nmap";; arping|ping) pk="$pk iputils";; dig) pk="$pk bind-utils";;
                       nc) pk="$pk nmap-ncat";; bash) pk="$pk bash";; timeout) pk="$pk coreutils";; esac
        elif have apk; then
            case $m in nmap) pk="$pk nmap";; arping) pk="$pk arping";; dig) pk="$pk bind-tools";;
                       nc) pk="$pk netcat-openbsd";; ping) pk="$pk iputils";; bash) pk="$pk bash";; timeout) pk="$pk coreutils";; esac
        elif have pacman; then
            case $m in nmap) pk="$pk nmap";; arping|ping) pk="$pk iputils";; dig) pk="$pk bind";;
                       nc) pk="$pk openbsd-netcat";; bash) pk="$pk bash";; timeout) pk="$pk coreutils";; esac
        elif have zypper; then
            case $m in nmap) pk="$pk nmap";; arping|ping) pk="$pk iputils";; dig) pk="$pk bind-utils";;
                       nc) pk="$pk netcat-openbsd";; bash) pk="$pk bash";; timeout) pk="$pk coreutils";; esac
        elif have brew; then
            case $m in nmap) pk="$pk nmap";; arping) pk="$pk arping";; bash) pk="$pk bash";; timeout) pk="$pk coreutils";; esac
        fi
    done
    pk=$(printf '%s\n' $pk | sort -u | tr '\n' ' ')
    [ -n "${pk# }" ] || { warn "no known package mapping for:$missing — install them manually."; return 0; }

    if   have apt-get; then ${SUDO:+$SUDO} apt-get update -qq || true; ${SUDO:+$SUDO} env DEBIAN_FRONTEND=noninteractive apt-get install -y $pk
    elif have dnf;     then ${SUDO:+$SUDO} dnf install -y $pk
    elif have yum;     then ${SUDO:+$SUDO} yum install -y $pk
    elif have apk;     then ${SUDO:+$SUDO} apk add --no-cache $pk
    elif have pacman;  then ${SUDO:+$SUDO} pacman -Sy --noconfirm --needed $pk
    elif have zypper;  then ${SUDO:+$SUDO} zypper --non-interactive install $pk
    elif have brew;    then brew install $pk
    else warn "no supported package manager found; install manually:$missing"; return 0
    fi || warn "some packages failed to install — asset-reachability still works with what is present."
}

if [ "$WITH_DEPS" -eq 1 ]; then
    if [ "$(id -u)" -ne 0 ] && [ -z "$SUDO" ] && ! have brew; then
        warn "not root and no sudo: skipping dependency install (use --no-deps to silence)."
    else
        install_deps
    fi
fi

# --- download + verify ------------------------------------------------------
BASE="${AR_BASE_URL:-https://raw.githubusercontent.com/$REPO/$REF}"
TMP=$(mktemp -d 2>/dev/null || mktemp -d -t arinstall)
trap 'rm -rf "$TMP"' EXIT INT TERM

fetch() {   # url dest
    if have curl; then curl -fsSL --retry 3 -o "$2" "$1"
    elif have wget; then wget -qO "$2" "$1"
    else die "need curl or wget."; fi
}

info "downloading $SCRIPT_NAME ($REPO@$REF)"
fetch "$BASE/$SCRIPT_NAME" "$TMP/$SCRIPT_NAME" || die "download failed: $BASE/$SCRIPT_NAME"

head -n 1 "$TMP/$SCRIPT_NAME" | grep -q '^#!/usr/bin/env bash' || die "downloaded file isn't the expected script (bad shebang)."
if grep -q "$(printf '\r')" "$TMP/$SCRIPT_NAME"; then die "downloaded script has CRLF line endings; refusing to install."; fi
bash -n "$TMP/$SCRIPT_NAME" || die "downloaded script failed a bash syntax check."

sha_of() { if have sha256sum; then sha256sum "$1" | cut -d' ' -f1; elif have shasum; then shasum -a 256 "$1" | cut -d' ' -f1; else echo ""; fi; }
actual=$(sha_of "$TMP/$SCRIPT_NAME")
expected="${AR_SHA256:-}"
if [ -z "$expected" ] && fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" 2>/dev/null; then
    expected=$(awk -v f="$SCRIPT_NAME" '$2==f || $2=="*"f {print $1; exit}' "$TMP/SHA256SUMS")
fi
if [ -n "$actual" ] && [ -n "$expected" ]; then
    [ "$actual" = "$expected" ] || die "checksum mismatch (expected $expected, got $actual)."
    ok "sha256 verified"
else
    warn "couldn't verify checksum (no sha256 tool or no SHA256SUMS); continuing."
fi

# --- install ----------------------------------------------------------------
${PFX_SUDO:+$PFX_SUDO} mkdir -p "$PREFIX"
${PFX_SUDO:+$PFX_SUDO} install -m 0755 "$TMP/$SCRIPT_NAME" "$DEST"
ok "installed $DEST"

case ":$PATH:" in
    *":$PREFIX:"*) ;;
    *) warn "$PREFIX is not on your PATH. Add:  export PATH=\"$PREFIX:\$PATH\"" ;;
esac

ver=$("$DEST" --version 2>&1) || die "installed command failed to run: $ver"
ok "$ver"
printf '\nTry it:  %s%s -c 192.168.1.0/24 -m ping%s   (only scan networks you are authorized to test)\n' "$B" "$CMD_NAME" "$N"
