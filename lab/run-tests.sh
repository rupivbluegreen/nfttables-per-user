#!/usr/bin/env bash
# tunnelfw lab end-to-end tests.
#
# Brings up the Samba AD DC + Rocky 9 bastion + target lab, then verifies:
#   - AD users tunnel through sshd :2222 only to their group's destinations
#     (both sshd PermitOpen and nftables enforce this)
#   - the nftables layer blocks independently of sshd (raw /dev/tcp probes)
#   - default-deny for scope users with no policy group
#   - AD group membership changes take effect after `tunnelfw.sh sync`
#   - the port-22 daemon (BoKS stand-in) coexists untouched
set -uo pipefail
cd "$(dirname "$0")"

BASTION=172.30.0.20
TARGET=172.30.0.30
SSH_OPTS=(-p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o ConnectTimeout=8 -o BatchMode=yes -o IdentitiesOnly=yes -o LogLevel=ERROR)
PASS=0 FAIL=0

ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

# ---- ssh-layer probe: banner via `ssh -W` through the tunnel daemon --------
probe_ssh() {  # user host port
    timeout 15 ssh "${SSH_OPTS[@]}" -i "keys/$1" "$1@$BASTION" -W "$2:$3" </dev/null 2>/dev/null
}
# ---- fw-layer probe: raw TCP as the AD user's uid, bypassing sshd ----------
probe_fw() {   # user host port
    local uid
    uid=$(docker exec tfw-bastion id -u "$1") || return 1
    docker exec -u "$uid" tfw-bastion timeout 6 bash -c "cat </dev/tcp/$2/$3" 2>/dev/null
}

expect() {     # ssh|fw user host port expected-banner|BLOCKED description
    local kind=$1 user=$2 host=$3 port=$4 want=$5 desc=$6 got
    got=$("probe_$kind" "$user" "$host" "$port")
    if [ "$want" = BLOCKED ]; then
        [ -z "$got" ] && ok "$desc" || bad "$desc (expected blocked, got: $got)"
    else
        [ "$got" = "$want" ] && ok "$desc" || bad "$desc (expected $want, got: '$got')"
    fi
}

echo "== generating user keys =="
mkdir -p keys/pub
for u in alice bob charlie; do
    [ -f "keys/$u" ] || ssh-keygen -q -t ed25519 -N '' -C "$u@lab" -f "keys/$u"
    cp "keys/$u.pub" "keys/pub/$u"
done

echo "== bringing up lab (this builds 3 images on first run) =="
docker compose up -d --build || exit 1

echo "== waiting for bastion (AD provision + join + sssd) =="
# Gate on a per-container-lifetime marker file (fresh each entrypoint run),
# NOT on cumulative `docker compose logs` which can match a stale ready line
# from a previous incarnation and let tests run against a half-initialized host.
ready=0
for i in $(seq 1 180); do
    if docker exec tfw-bastion test -f /run/bastion-ready 2>/dev/null; then ready=1; break; fi
    sleep 2
done
if [ "$ready" -ne 1 ]; then
    echo "bastion never became ready; recent logs:"
    docker compose logs --tail 60 dc bastion
    exit 1
fi
echo "bastion ready."

echo "== sshd + nftables end-to-end (ssh -W through :2222) =="
expect ssh alice   "$TARGET" 5432 DB-OK   "alice   -> target:5432 allowed (dbadmins)"
expect ssh alice   "$TARGET" 80   BLOCKED "alice   -> target:80   blocked"
expect ssh bob     "$TARGET" 80   HTTP-OK "bob     -> target:80   allowed (webdevs)"
expect ssh bob     "$TARGET" 5432 BLOCKED "bob     -> target:5432 blocked"
expect ssh charlie "$TARGET" 80   BLOCKED "charlie -> target:80   blocked (no policy group)"
expect ssh charlie "$TARGET" 5432 BLOCKED "charlie -> target:5432 blocked (no policy group)"

echo "== nftables layer alone (raw /dev/tcp as the user's uid) =="
expect fw alice   "$TARGET" 5432 DB-OK   "fw: alice   -> :5432 allowed"
expect fw alice   "$TARGET" 80   BLOCKED "fw: alice   -> :80   dropped"
expect fw bob     "$TARGET" 80   HTTP-OK "fw: bob     -> :80   allowed"
expect fw charlie "$TARGET" 5432 BLOCKED "fw: charlie -> :5432 dropped (default-deny)"
got=$(docker exec tfw-bastion timeout 6 bash -c "cat </dev/tcp/$TARGET/80" 2>/dev/null)
[ "$got" = HTTP-OK ] && ok "fw: root (unmanaged) -> :80 unaffected" \
                     || bad "fw: root (unmanaged) -> :80 unaffected (got: '$got')"

echo "== drop counter =="
if docker exec tfw-bastion nft list chain inet tunnelfw managed \
        | grep -qE 'counter packets [1-9][0-9]* bytes [0-9]+ drop'; then
    ok "default-deny drop counter incremented"
else
    bad "default-deny drop counter incremented"
fi

echo "== AD membership change + sync (fw layer) =="
docker exec tfw-dc samba-tool group addmembers webdevs alice >/dev/null
docker exec tfw-bastion bash -c 'sss_cache -E && /usr/local/sbin/tunnelfw.sh sync'
expect fw alice "$TARGET" 80 HTTP-OK "alice -> :80 allowed after joining webdevs + sync"
docker exec tfw-dc samba-tool group removemembers webdevs alice >/dev/null
docker exec tfw-bastion bash -c 'sss_cache -E && /usr/local/sbin/tunnelfw.sh sync'
expect fw alice "$TARGET" 80 BLOCKED "alice -> :80 re-blocked after removal + sync"

echo "== dual-daemon coexistence =="
banner=$(timeout 5 bash -c "exec 3<>/dev/tcp/$BASTION/22 && head -c 7 <&3" 2>/dev/null)
[ "$banner" = "SSH-2.0" ] && ok "port 22 sshd (BoKS stand-in) still serving" \
                          || bad "port 22 sshd (BoKS stand-in) still serving (got: '$banner')"
if timeout 15 ssh "${SSH_OPTS[@]}" -i keys/alice "alice@$BASTION" true 2>/dev/null; then
    bad "interactive exec denied on :2222"
else
    ok "interactive exec denied on :2222 (ForceCommand /bin/false)"
fi

echo
echo "RESULT: $PASS passed, $FAIL failed"
echo "(lab left running; tear down with: docker compose -f $(pwd)/docker-compose.yml down -v)"
[ "$FAIL" -eq 0 ]
