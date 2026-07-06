#!/usr/bin/env bash
# sshd-tunnel-setup.sh — install the tunnel-only sshd so it uses its OWN PAM
# service name (sshd-tunnel), independent of the BoKS-managed sshd on port 22.
#
# OpenSSH picks the PAM service name differently by version, so the mechanism is
# version-gated (verified against OpenSSH source + RHEL build spec):
#
#   OpenSSH <= 9.7 (RHEL 9.0-9.7, 8.7p1): service name = argv[0] basename, NO
#       directive. We run the daemon as /usr/sbin/sshd-tunnel (a symlink to
#       sshd) so it reads /etc/pam.d/sshd-tunnel.
#   OpenSSH >= 9.8 (RHEL 9.8+, Rocky/CentOS Stream 9, 9.9p1): argv[0] is ignored;
#       a PAMServiceName directive selects it. We drop "PAMServiceName
#       sshd-tunnel" into sshd_tunnel_config.d/.
#
# The symlink is created either way (uniform ExecStart, load-bearing only on
# <=9.7); the directive is written only on >=9.8 (it is an unknown keyword on
# 8.7p1 and would fail sshd -t).
#
# Usage:
#   sudo ./sshd-tunnel-setup.sh                 # detect + install (needs root)
#   ./sshd-tunnel-setup.sh --print-mechanism "OpenSSH_9.9p1"
#   ./sshd-tunnel-setup.sh --self-test          # verify version detection
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSHD_BIN="$(command -v sshd || echo /usr/sbin/sshd)"
TUNNEL_BIN=/usr/sbin/sshd-tunnel
TUNNEL_CONF=/etc/ssh/sshd_tunnel_config
DROPIN_DIR=/etc/ssh/sshd_tunnel_config.d
DROPIN=$DROPIN_DIR/00-pamservice.conf
PAM_FILE=/etc/pam.d/sshd-tunnel

log()  { printf 'sshd-tunnel-setup: %s\n' "$*" >&2; }
die()  { printf 'sshd-tunnel-setup: ERROR: %s\n' "$*" >&2; exit 1; }

# pam_mechanism <version-string> -> "directive" (>=9.8) | "symlink" (<=9.7)
# Accepts "OpenSSH_9.9p1, ..." or a bare "9.9". Isolated for unit testing.
pam_mechanism() {
    local v="$1" mm maj min
    mm=$(printf '%s' "$v" | sed -n 's/.*OpenSSH_\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
    [ -z "$mm" ] && mm=$(printf '%s' "$v" | sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
    [ -z "$mm" ] && { echo unknown; return 1; }
    maj=${mm%.*}; min=${mm#*.}
    if [ "$maj" -gt 9 ] || { [ "$maj" -eq 9 ] && [ "$min" -ge 8 ]; }; then
        echo directive
    else
        echo symlink
    fi
}

detect_mechanism() {
    local ver
    ver=$(ssh -V 2>&1 || true)
    [ -n "$ver" ] || die "cannot determine OpenSSH version (ssh -V produced nothing)"
    pam_mechanism "$ver" || die "unrecognized OpenSSH version string: $ver"
}

self_test() {
    local ok=1 got exp
    for pair in "OpenSSH_8.7p1=symlink" "OpenSSH_9.9p1=directive" \
                "OpenSSH_9.6p1=symlink" "OpenSSH_9.8p1=directive" \
                "OpenSSH_10.0p1=directive" "9.7=symlink"; do
        exp=${pair#*=}; got=$(pam_mechanism "${pair%=*}") || got=err
        if [ "$got" = "$exp" ]; then
            echo "  ok: ${pair%=*} -> $got"
        else
            echo "  FAIL: ${pair%=*} -> $got (expected $exp)"; ok=0
        fi
    done
    [ "$ok" = 1 ] && { echo "self-test PASS"; exit 0; } || { echo "self-test FAIL"; exit 1; }
}

install_all() {
    [ "$(id -u)" = 0 ] || die "must run as root (try sudo)"
    local mech; mech=$(detect_mechanism)
    log "OpenSSH mechanism: $mech ($(ssh -V 2>&1))"

    # 1. symlink (always; uniform ExecStart, selects the PAM service on <=9.7)
    ln -sfn "$(readlink -f "$SSHD_BIN")" "$TUNNEL_BIN"
    log "symlink $TUNNEL_BIN -> $(readlink -f "$SSHD_BIN")"

    # 2. config + drop-in dir + PAM stack
    install -m 0644 "$SRC_DIR/sshd/sshd_tunnel_config" "$TUNNEL_CONF"
    install -d -m 0755 "$DROPIN_DIR"
    install -m 0644 "$SRC_DIR/sshd/pam.d/sshd-tunnel" "$PAM_FILE"
    log "installed $TUNNEL_CONF and $PAM_FILE"

    # 3. PAMServiceName directive (>=9.8 only; unknown keyword on 8.7p1)
    if [ "$mech" = directive ]; then
        printf '# %s\nPAMServiceName sshd-tunnel\n' \
            "written by sshd-tunnel-setup.sh (OpenSSH >= 9.8)" > "$DROPIN"
        log "wrote $DROPIN (PAMServiceName sshd-tunnel)"
    else
        rm -f "$DROPIN"
        log "no directive needed; PAM service comes from the sshd-tunnel binary name"
    fi

    # 4. SELinux port label (best effort; no-op where SELinux is not enforced)
    if command -v semanage >/dev/null 2>&1; then
        semanage port -a -t ssh_port_t -p tcp 2222 2>/dev/null \
            || semanage port -m -t ssh_port_t -p tcp 2222 2>/dev/null \
            || log "semanage: port 2222 already labeled or not applicable"
    else
        log "semanage not present; skipping SELinux port label (do it on the real host)"
    fi

    # 5. validate
    "$TUNNEL_BIN" -t -f "$TUNNEL_CONF" \
        || die "sshd config test failed for $TUNNEL_CONF"
    log "OK — validated. Start with: systemctl enable --now sshd-tunnel.service"
}

case "${1:-}" in
    --self-test)        self_test ;;
    --print-mechanism)  pam_mechanism "${2:?need a version string}" ;;
    "")                 install_all ;;
    -h|--help)          sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)                  die "unknown argument: $1 (see --help)" ;;
esac
