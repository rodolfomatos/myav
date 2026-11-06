#!/usr/bin/env bash
# myav system installer — the only part of myav that needs root.
#
# Why this file exists
# --------------------
# The Python code runs as your normal user. It cannot install packages, write to
# /etc, or start system services without asking the operating system for privilege.
# This script does those four jobs once, explains each command before running it,
# and is safe to run twice.
#
# Safety contract
# ---------------
#   * no argument            -> dry run: print every command, change nothing
#   * --dry-run              -> same, explicitly
#   * --apply                -> actually install (must be root)
#   * --force                -> reinstall packages even when already present
#   * --no-clamd             -> skip the on-access daemon configuration
#   * --help                 -> this text
#
# It never runs `sudo` on your behalf, never deletes a file, never disables an
# existing antivirus, and never writes below /mnt/c (the Windows disk).
set -euo pipefail

APPLY=0
FORCE=0
CONFIGURE_CLAMD=1

usage() {
  sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'
}

for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --dry-run) APPLY=0 ;;
    --force) FORCE=1 ;;
    --no-clamd) CONFIGURE_CLAMD=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done

log()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
run() {
  if [ "$APPLY" -eq 1 ]; then
    printf '  $ %s\n' "$*"
    "$@"
  else
    printf '  WOULD RUN: %s\n' "$*"
  fi
}

if [ "$(id -u)" -eq 0 ]; then
  IS_ROOT=1
else
  IS_ROOT=0
fi

if [ "$APPLY" -eq 1 ] && [ "$IS_ROOT" -eq 0 ]; then
  cat >&2 <<'EOF'
myav: --apply needs root because it installs packages and writes to /etc.

Ask the operator (the human with the administrator password) to run:

    sudo ./scripts/install-system.sh --apply

This script will not call sudo for you: privilege must be granted explicitly.
EOF
  exit 3
fi

if [ "$APPLY" -eq 1 ] && [ "${MYAV_FORCE:-0}" != "1" ]; then
  note "You are about to change this machine. Review the dry run first:"
  note "    ./scripts/install-system.sh --dry-run"
fi

OS="$(uname -s)"
DISTRO="unknown"
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO="${ID:-unknown}"
fi

log "1/6 — Detecting the platform"
note "operating system: $OS"
note "distribution:     $DISTRO"
note "running as root:  $([ "$IS_ROOT" -eq 1 ] && echo yes || echo no)"
note "mode:             $([ "$APPLY" -eq 1 ] && echo APPLY || echo DRY RUN)"

if [ "$OS" = "Linux" ] && [ -d /mnt/c ]; then
  note "WSL detected: systemd may be offline; the script handles that below."
fi

have() { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------------------
log "2/6 — Installing ClamAV and YARA"
# --------------------------------------------------------------------------
# Why: ClamAV provides the signature database and scanner. YARA provides pattern
# rules for scripts, webshells and miner configs. Both are scanning engines; the
# watcher that calls them is plain Python and needs no root.
install_debian() {
  local packages=(clamav clamav-daemon clamav-freshclam yara python3-tk)
  local missing=()
  for pkg in "${packages[@]}"; do
    if [ "$FORCE" -eq 1 ] || ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done
  if [ "${#missing[@]}" -eq 0 ] && [ "$FORCE" -eq 0 ]; then
    note "already installed: ${packages[*]}"
    return
  fi
  note "packages to install: ${missing[*]}"
  run apt-get update
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
}

install_fedora() {
  local packages=(clamav clamav-update clamd yara python3-tkinter)
  note "packages: ${packages[*]}"
  run dnf install -y "${packages[@]}"
}

install_arch() {
  note "packages: clamav yara tk"
  run pacman -S --needed --noconfirm clamav yara tk
}

install_macos() {
  if ! have brew; then
    note "Homebrew is not installed. Install it from https://brew.sh, then re-run this script."
    note "No system change was made."
    return
  fi
  run brew install clamav yara
}

case "$OS" in
  Linux)
    case "$DISTRO" in
      ubuntu|debian|linuxmint|pop|kali|raspbian) install_debian ;;
      fedora|rhel|centos|rocky|almalinux) install_fedora ;;
      arch|manjaro|endeavouros) install_arch ;;
      *)
        note "Unrecognised distribution '$DISTRO'."
        note "Install these packages with your package manager, then re-run:"
        note "    clamav  clamav-daemon  clamav-freshclam  yara"
        ;;
    esac
    ;;
  Darwin) install_macos ;;
  *)
    note "This installer supports Linux and macOS."
    note "On Windows, run myav inside WSL (Ubuntu) and use this script there."
    ;;
esac

# --------------------------------------------------------------------------
log "3/6 — Updating the signature database once"
# --------------------------------------------------------------------------
# Why: a freshly installed ClamAV has an old or empty database. One update now
# means the first scan is meaningful. The nightly job keeps it fresh afterwards.
if have freshclam; then
  # If the freshclam daemon is already running (started by the package postinst
  # on systemd hosts), it is already keeping the database fresh. Running a
  # one-shot freshclam here would collide on /var/log/clamav/freshclam.log's
  # lock, so we skip it and let the daemon handle the updates.
  if pgrep -x freshclam >/dev/null 2>&1; then
    note "clamav-freshclam daemon is already running — signature updates are handled by it; skipping one-shot freshclam."
  else
    run freshclam
  fi
else
  note "freshclam is not on PATH yet; skipping the first update."
fi

# --------------------------------------------------------------------------
log "4/6 — Configuring clamd (loopback only)"
# --------------------------------------------------------------------------
# Why: clamd keeps signatures in memory, so scanning is fast. It listens on
# 127.0.0.1:3310 — never on a public interface — and on a local Unix socket.
# A backup of the previous configuration is kept once as clamd.conf.bak.
if [ "$CONFIGURE_CLAMD" -eq 1 ] && [ "$OS" = "Linux" ]; then
  if [ -f /etc/clamav/clamd.conf ]; then
    if [ ! -f /etc/clamav/clamd.conf.bak ]; then
      run cp -a /etc/clamav/clamd.conf /etc/clamav/clamd.conf.bak
    else
      note "backup already exists: /etc/clamav/clamd.conf.bak (kept untouched)"
    fi
    if [ "$APPLY" -eq 1 ]; then
      cat >> /etc/clamav/clamd.conf <<'EOF'

# Added by myav. Remove these lines to return to the distribution defaults.
TCPSocket 3310
TCPAddr 127.0.0.1
LocalSocket /run/clamav/clamd.ctl
MaxThreads 4
Foreground true
EOF
      note "appended myav settings to /etc/clamav/clamd.conf"
    else
      note "WOULD APPEND: /etc/clamav/clamd.conf (TCPSocket 3310, TCPAddr 127.0.0.1)"
    fi
  else
    note "/etc/clamav/clamd.conf not found — skipping clamd configuration."
  fi

  # Start the services when systemd is actually running. On WSL it is often not.
  if have systemctl && systemctl is-system-running >/dev/null 2>&1; then
    run systemctl enable --now clamav-freshclam
    run systemctl enable --now clamav-daemon
  else
    note "systemd is not available. Starting clamd directly instead:"
    # clamd drops privileges to the clamav user (User clamav in clamd.conf).
    # Create the socket directory with the right ownership before starting,
    # otherwise clamd cannot bind its socket and fails with "Permission denied".
    if have clamd; then
      CLAMD_BIN="$(command -v clamd)"
    elif [ -x /usr/sbin/clamd ]; then
      CLAMD_BIN="/usr/sbin/clamd"
    else
      note "clamd binary not found; myav will fall back to clamscan per file."
      CLAMD_BIN=""
    fi
    if [ -n "${CLAMD_BIN:-}" ]; then
      # Create socket directory with correct ownership. Do NOT silence errors:
      # if we cannot create it, clamd will fail to start.
      if [ "$(id -u)" -eq 0 ]; then
        install -d -o clamav -g clamav -m 755 /var/run/clamav
        chown clamav:clamav /var/run/clamav
        chmod 755 /var/run/clamav
      fi
      run runuser -u clamav -- "$CLAMD_BIN"
    fi
  fi
else
  note "clamd configuration skipped."
fi

# --------------------------------------------------------------------------
log "5/6 — Checking the result"
# --------------------------------------------------------------------------
if [ "$APPLY" -eq 1 ]; then
  for binary in clamscan clamdscan freshclam yara; do
    if have "$binary"; then
      note "found: $binary ($(command -v "$binary"))"
    else
      note "MISSING: $binary"
    fi
  done
  if have clamscan; then
    note "ClamAV version: $(clamscan --version 2>/dev/null | head -n 1)"
  fi
  if have yara; then
    note "YARA version: $(yara --version 2>/dev/null | head -n 1)"
  fi
else
  note "Dry run: nothing was installed, configured or started."
fi

# --------------------------------------------------------------------------
log "6/6 — What to do next (as your normal user, not root)"
# --------------------------------------------------------------------------
cat <<'EOF'
  # 1. Check that everything myav needs is visible
  ./bin/myav doctor

  # 2. Download the pinned YARA rule pack (review the licence first)
  ./bin/myav rules fetch --accept-license

  # 3. Prove the whole chain with the harmless EICAR test file
  ./bin/myav selftest

  # 4. Install the recurring jobs (watch at login, update 02:30, scan Sunday 03:00)
  ./bin/myav schedules install --yes

  # 5. Read the reports
  ./bin/myav report
EOF

if [ "$APPLY" -eq 0 ]; then
  printf '\nThis was a dry run. Review the commands above, then run:\n'
  printf '    sudo %s --apply\n\n' "$0"
fi
