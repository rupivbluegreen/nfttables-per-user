#!/usr/bin/env bash
# tunnelfw — per-AD-group egress policy for an SSH tunneling bastion.
#
# Outbound traffic is matched by socket owner UID (nftables `meta skuid`).
# Group membership is resolved with getent, which behaves identically for
# local groups and SSSD/AD-backed groups, into per-group nftables uid sets.
# Users in the managed scope with no matching group policy are default-denied.
#
# Commands:
#   apply         parse config, resolve groups, atomically load full ruleset
#   sync          refresh uid sets only (for a systemd timer; needs prior apply)
#   check         dry-run: print resolved members and validate generated ruleset
#   status        show groups, members, policies and the drop counter
#   sshd-snippet  emit sshd_config Match blocks (PermitOpen policy) to stdout
#   flush         delete the tunnelfw table entirely (touches nothing else)
#
# Config layout (override dir with -c DIR or TUNNELFW_CONFIG):
#   /etc/tunnelfw/tunnelfw.conf        resolvers=..., scope_groups=...
#   /etc/tunnelfw/groups.d/NAME.conf   match=<getent group>  allow=proto/dest:port
set -euo pipefail

CONFIG_DIR="${TUNNELFW_CONFIG:-/etc/tunnelfw}"
TABLE_FAM="inet"
TABLE_NAME="tunnelfw"
TABLE="$TABLE_FAM $TABLE_NAME"
RULESET_OUT="/run/tunnelfw.nft"
FORCE=0
RESOLVE_FAILED=0        # set by resolve_all if any group could not be resolved

log()  { printf 'tunnelfw: %s\n' "$*" >&2; }
warn() { printf 'tunnelfw: WARNING: %s\n' "$*" >&2; }
die()  { printf 'tunnelfw: ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ---------------------------------------------------------------- config ---

RESOLVERS=()            # IPv4 DNS servers managed users may reach
SCOPE_GROUPS=()         # groups managed (default-denied) even without policy
POLICY_NAMES=()         # sorted policy names (groups.d file basenames)
declare -A P_MATCH      # policy -> getent group name
declare -A P_TCP        # policy -> newline-separated "dest . port" tcp entries
declare -A P_UDP        # policy -> newline-separated "dest . port" udp entries
declare -A P_UIDS       # policy -> space-separated resolved uids
SCOPE_UIDS=""

trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; printf '%s' "${s%"${s##*[![:space:]]}"}"; }

parse_spec() {          # parse_spec <policy> <proto/dest:port>
    local policy="$1" spec="$2" proto rest dest port
    proto="${spec%%/*}"
    rest="${spec#*/}"
    [[ "$rest" == *:* ]] || die "bad spec '$spec' in $policy: missing :port"
    port="${rest##*:}"
    dest="${rest%:*}"
    [[ "$proto" == tcp || "$proto" == udp ]] \
        || die "bad spec '$spec' in $policy: proto must be tcp or udp"
    [[ "$port" =~ ^[0-9]+(-[0-9]+)?$ ]] \
        || die "bad spec '$spec' in $policy: port must be N or N-M"
    [[ "$dest" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]] \
        || die "bad spec '$spec' in $policy: dest must be IPv4 or CIDR"
    if [[ "$proto" == tcp ]]; then
        P_TCP[$policy]+="$dest . $port"$'\n'
    else
        P_UDP[$policy]+="$dest . $port"$'\n'
    fi
}

load_config() {
    [[ -d "$CONFIG_DIR" ]] || die "config dir $CONFIG_DIR not found"
    local line key val f policy
    if [[ -f "$CONFIG_DIR/tunnelfw.conf" ]]; then
        while IFS= read -r line; do
            line="${line%%#*}"; line=$(trim "$line")
            [[ -z "$line" ]] && continue
            key="${line%%=*}"; val=$(trim "${line#*=}")
            case "$(trim "$key")" in
                resolvers)    read -ra RESOLVERS <<<"$val" ;;
                scope_groups) read -ra SCOPE_GROUPS <<<"$val" ;;
                *) warn "unknown key '$key' in tunnelfw.conf" ;;
            esac
        done <"$CONFIG_DIR/tunnelfw.conf"
    fi
    if ((${#RESOLVERS[@]} == 0)) && [[ -f /etc/resolv.conf ]]; then
        while read -r key val _; do
            [[ "$key" == nameserver && "$val" =~ ^[0-9.]+$ ]] && RESOLVERS+=("$val")
        done </etc/resolv.conf
    fi
    shopt -s nullglob
    for f in "$CONFIG_DIR"/groups.d/*.conf; do
        policy="$(basename "$f" .conf)"
        [[ "$policy" =~ ^[a-zA-Z0-9_]+$ ]] \
            || die "policy file name '$policy' must be alphanumeric/underscore"
        POLICY_NAMES+=("$policy")
        P_MATCH[$policy]=""; P_TCP[$policy]=""; P_UDP[$policy]=""
        while IFS= read -r line; do
            line="${line%%#*}"; line=$(trim "$line")
            [[ -z "$line" ]] && continue
            key=$(trim "${line%%=*}"); val=$(trim "${line#*=}")
            case "$key" in
                match) P_MATCH[$policy]="$val" ;;
                allow) local s; for s in $val; do parse_spec "$policy" "$s"; done ;;
                *) warn "unknown key '$key' in $f" ;;
            esac
        done <"$f"
        [[ -n "${P_MATCH[$policy]}" ]] || die "$f: missing match=<group>"
    done
    shopt -u nullglob
    ((${#POLICY_NAMES[@]} > 0)) || warn "no policies defined in $CONFIG_DIR/groups.d"
}

# ------------------------------------------------------------ resolution ---

resolve_group_uids() {  # resolve_group_uids <group> -> space-separated uids on stdout
    local group="$1" entry gid members m u uids=""
    if ! entry=$(getent group "$group"); then
        warn "group '$group' not resolvable via getent — leaving its set unchanged/empty"
        return 1
    fi
    gid=$(cut -d: -f3 <<<"$entry")
    members=$(cut -d: -f4 <<<"$entry")
    for m in ${members//,/ }; do
        if u=$(id -u "$m" 2>/dev/null); then
            uids+="$u "
        else
            warn "member '$m' of '$group' has no resolvable uid — skipped"
        fi
    done
    # local users whose *primary* group is this gid (AD users normally have a
    # supplementary policy group; local-file enumeration covers the local case)
    while IFS=: read -r _ _ u pgid _; do
        [[ "$pgid" == "$gid" ]] && uids+="$u "
    done < <(getent -s files passwd 2>/dev/null || true)
    local out=""
    for u in $(tr ' ' '\n' <<<"$uids" | sort -un); do
        if [[ "$u" == 0 ]]; then
            warn "group '$group' contains uid 0 — skipped (never manage root)"
            continue
        fi
        if [[ -n "${SUDO_UID:-}" && "$u" == "$SUDO_UID" && "$FORCE" != 1 ]]; then
            warn "group '$group' contains your own uid $u — skipped (use --force to include)"
            continue
        fi
        out+="$u "
    done
    printf '%s' "$out"
}

resolve_all() {
    local policy group out uids=""
    RESOLVE_FAILED=0
    # A group that resolves to zero members (out="") is a legitimate empty set;
    # a group getent can't resolve at all sets RESOLVE_FAILED. sync uses this to
    # avoid overwriting live sets with partial data during an AD/DC hiccup.
    for policy in "${POLICY_NAMES[@]}"; do
        if out=$(resolve_group_uids "${P_MATCH[$policy]}"); then
            P_UIDS[$policy]="$out"
        else
            P_UIDS[$policy]=""; RESOLVE_FAILED=1
        fi
    done
    for group in "${SCOPE_GROUPS[@]}"; do
        if out=$(resolve_group_uids "$group"); then
            uids+="$out "
        else
            RESOLVE_FAILED=1
        fi
    done
    SCOPE_UIDS=$(trim "$uids")
}

managed_uids() {        # union of all policy uids + scope uids
    { for p in "${POLICY_NAMES[@]}"; do printf '%s\n' ${P_UIDS[$p]:-}; done
      printf '%s\n' $SCOPE_UIDS; } | grep -v '^$' | sort -un | tr '\n' ' '
}

join_commas() { local IFS=', '; printf '%s' "$*"; }

# ------------------------------------------------------------- rendering ---

emit_elements() {       # emit_elements <set> <element>... (skips empty)
    local set="$1"; shift
    (($# == 0)) && return 0
    printf 'add element %s %s { %s }\n' "$TABLE" "$set" "$(join_commas "$@")"
}

emit_concat_elements() { # emit_concat_elements <set> <<<"dest . port lines"
    local set="$1" lines="$2" out=""
    while IFS= read -r l; do
        [[ -z "$l" ]] && continue
        out+="${out:+, }$l"
    done <<<"$lines"
    [[ -n "$out" ]] && printf 'add element %s %s { %s }\n' "$TABLE" "$set" "$out"
    return 0
}

emit_ruleset() {
    local p
    cat <<EOF
# Generated by tunnelfw.sh apply — do not edit; edit $CONFIG_DIR instead.
table $TABLE
delete table $TABLE
table $TABLE {
    set managed_uids { type uid; }
    set resolvers4   { type ipv4_addr; }
EOF
    for p in "${POLICY_NAMES[@]}"; do
        cat <<EOF
    set g_${p}_uid { type uid; }
    set g_${p}_tcp { type ipv4_addr . inet_service; flags interval; }
    set g_${p}_udp { type ipv4_addr . inet_service; flags interval; }
    chain pol_$p {
        ip daddr . tcp dport @g_${p}_tcp accept
        ip daddr . udp dport @g_${p}_udp accept
    }
EOF
    done
    cat <<EOF
    chain managed {
        ct state established,related accept
        oifname "lo" accept
        ip daddr @resolvers4 udp dport 53 accept
        ip daddr @resolvers4 tcp dport 53 accept
EOF
    for p in "${POLICY_NAMES[@]}"; do
        printf '        meta skuid @g_%s_uid jump pol_%s\n' "$p" "$p"
    done
    cat <<EOF
        counter drop
    }
    chain output {
        type filter hook output priority filter; policy accept;
        meta skuid @managed_uids jump managed
    }
}
EOF
    emit_elements managed_uids $(managed_uids)
    emit_elements resolvers4 "${RESOLVERS[@]}"
    for p in "${POLICY_NAMES[@]}"; do
        emit_elements "g_${p}_uid" ${P_UIDS[$p]:-}
        emit_concat_elements "g_${p}_tcp" "${P_TCP[$p]:-}"
        emit_concat_elements "g_${p}_udp" "${P_UDP[$p]:-}"
    done
}

emit_sync() {
    local p
    printf 'flush set %s managed_uids\n' "$TABLE"
    emit_elements managed_uids $(managed_uids)
    for p in "${POLICY_NAMES[@]}"; do
        printf 'flush set %s g_%s_uid\n' "$TABLE" "$p"
        emit_elements "g_${p}_uid" ${P_UIDS[$p]:-}
    done
}

emit_sshd_snippet() {
    local p match entries dest port line has_cidr
    cat <<EOF
# Generated by tunnelfw.sh sshd-snippet — per-group tunnel destinations.
# Include from the tunnel sshd config; order matters (first match wins),
# specific groups first, scope catch-all last.
EOF
    for p in "${POLICY_NAMES[@]}"; do
        match="${P_MATCH[$p]}"
        [[ "$match" == *" "* ]] && match="\"$match\""
        printf 'Match Group %s\n' "$match"
        entries=""; has_cidr=0
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            dest="${line%% . *}"; port="${line##* . }"
            if [[ "$dest" == */* || "$port" == *-* ]]; then
                has_cidr=1
            else
                entries+="${entries:+ }$dest:$port"
            fi
        done <<<"${P_TCP[$p]:-}"
        if [[ "$has_cidr" == 1 ]]; then
            printf '    AllowTcpForwarding yes\n'
            printf '    # CIDR/range specs cannot be expressed in PermitOpen;\n'
            printf '    # nftables enforces the full policy for this group.\n'
            printf '    PermitOpen any\n'
        elif [[ -n "$entries" ]]; then
            printf '    AllowTcpForwarding yes\n'
            printf '    PermitOpen %s\n' "$entries"
        else
            printf '    # no tcp destinations for this group\n'
            printf '    AllowTcpForwarding no\n'
        fi
    done
    if ((${#SCOPE_GROUPS[@]} > 0)); then
        printf 'Match Group %s\n' "$(join_commas "${SCOPE_GROUPS[@]}" | tr -d ' ')"
        printf '    AllowTcpForwarding no\n'
    fi
}

# --------------------------------------------------------------- actions ---

require_root() { [[ $EUID -eq 0 ]] || die "must run as root (try sudo)"; }

table_exists() { nft list table $TABLE >/dev/null 2>&1; }

cmd_apply() {
    require_root; load_config; resolve_all
    emit_ruleset >"$RULESET_OUT"
    nft -c -f "$RULESET_OUT" || die "generated ruleset failed validation ($RULESET_OUT)"
    nft -f "$RULESET_OUT"
    log "applied: $(wc -l <"$RULESET_OUT") lines, managed uids: [$(managed_uids)]"
}

cmd_sync() {
    require_root
    table_exists || die "table $TABLE not loaded — run 'tunnelfw.sh apply' first"
    load_config; resolve_all
    # Fail closed on partial resolution: leave every live uid set exactly as it
    # is rather than flushing a group to empty because the DC was briefly
    # unreachable. Nonzero exit surfaces the degraded sync to the systemd timer.
    if [[ "$RESOLVE_FAILED" == 1 ]]; then
        die "one or more groups did not resolve — live uid sets left unchanged"
    fi
    emit_sync | nft -f -
    log "synced: managed uids: [$(managed_uids)]"
}

cmd_check() {
    require_root; load_config; resolve_all
    local p
    for p in "${POLICY_NAMES[@]}"; do
        log "policy $p: group='${P_MATCH[$p]}' uids=[$(trim "${P_UIDS[$p]:-}")]"
    done
    log "scope uids: [$SCOPE_UIDS]"
    emit_ruleset
    emit_ruleset | nft -c -f - && log "ruleset OK (dry-run passed)"
}

cmd_status() {
    require_root; load_config; resolve_all
    table_exists || die "table $TABLE not loaded — run 'tunnelfw.sh apply' first"
    local p
    printf '=== tunnelfw status ===\n'
    for p in "${POLICY_NAMES[@]}"; do
        printf 'policy %-16s group=%-20s live-uids=[%s]\n' \
            "$p" "${P_MATCH[$p]}" "$(trim "${P_UIDS[$p]:-}")"
        printf '  loaded uid set: %s\n' \
            "$(nft list set $TABLE "g_${p}_uid" 2>/dev/null | grep -o 'elements = {[^}]*}' || echo '(empty)')"
    done
    printf 'managed set:  %s\n' \
        "$(nft list set $TABLE managed_uids | grep -o 'elements = {[^}]*}' || echo '(empty)')"
    printf 'default-deny: %s\n' \
        "$(nft list chain $TABLE managed | grep -E 'counter.*drop' | sed 's/^ *//')"
}

cmd_flush() {
    require_root
    if table_exists; then
        nft delete table $TABLE
        log "table $TABLE deleted"
    else
        log "table $TABLE not loaded — nothing to do"
    fi
}

cmd_sshd_snippet() { load_config; emit_sshd_snippet; }

# ------------------------------------------------------------------ main ---

CMD=""
while (($# > 0)); do
    case "$1" in
        -c|--config) CONFIG_DIR="${2:?--config needs a directory}"; shift 2 ;;
        --force)     FORCE=1; shift ;;
        -h|--help)   usage 0 ;;
        -*)          die "unknown option $1" ;;
        *)           CMD="$1"; shift; break ;;
    esac
done

case "$CMD" in
    apply)        cmd_apply ;;
    sync)         cmd_sync ;;
    check)        cmd_check ;;
    status)       cmd_status ;;
    sshd-snippet) cmd_sshd_snippet ;;
    flush)        cmd_flush ;;
    "")           usage 1 ;;
    *)            die "unknown command '$CMD' (see --help)" ;;
esac
