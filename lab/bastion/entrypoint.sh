#!/bin/bash
# tunnelfw lab bastion: joins the Samba AD domain, starts sssd, applies the
# tunnelfw egress policy, then runs two sshds — port 22 (stand-in for the
# BoKS-managed daemon) and port 2222 (tunnel-only, from sshd_tunnel_config).
set -euo pipefail

# Clear any readiness marker left in the writable layer from a prior *restart*
# of this same container (on a fresh/recreated container /run is already empty).
# run-tests.sh gates on this file, not on cumulative `docker compose logs`.
rm -f /run/bastion-ready

REALM="${REALM:-TUNNEL.LAB}"
DOMAIN_LOWER="$(tr '[:upper:]' '[:lower:]' <<<"$REALM")"
ADMIN_PASS="${ADMIN_PASS:?ADMIN_PASS must be set}"

echo ">> waiting for DC SRV records"
for _ in $(seq 1 90); do
    host -t SRV "_ldap._tcp.$DOMAIN_LOWER" >/dev/null 2>&1 && break
    sleep 2
done
host -t SRV "_ldap._tcp.$DOMAIN_LOWER" >/dev/null || { echo "DC DNS never came up"; exit 1; }

if [ ! -f /etc/krb5.keytab ]; then
    echo ">> joining domain $DOMAIN_LOWER"
    printf '%s' "$ADMIN_PASS" | adcli join --stdin-password \
        --domain "$DOMAIN_LOWER" --login-user Administrator
fi

echo ">> installing tunnelfw + tunnel sshd (own PAM service) from /opt/tunnelfw"
install -m 0755 /opt/tunnelfw/tunnelfw.sh /usr/local/sbin/tunnelfw.sh
# Host keys must exist before the setup script's `sshd -t` validation. On a real
# RHEL host the sshd package generates these at install/boot; the minimal lab
# container needs it done explicitly, and before setup runs.
ssh-keygen -A
# Dogfood the real installer: creates /usr/sbin/sshd-tunnel, installs
# /etc/ssh/sshd_tunnel_config + /etc/pam.d/sshd-tunnel, and (on OpenSSH >= 9.8)
# the PAMServiceName drop-in.
/opt/tunnelfw/sshd-tunnel-setup.sh

# --- lab-only PAM isolation scaffolding -------------------------------------
# Marker fired from each stack's account phase records which PAM service ran.
# pam_deny on the port-22 (BoKS stand-in) stack is a NEGATIVE CONTROL: if the
# tunnel daemon shared that stack the :2222 tests would fail, so their passing
# proves :2222 uses the separate sshd-tunnel stack.
cat > /usr/local/bin/pam-marker <<'EOF'
#!/bin/sh
echo "$PAM_SERVICE:$PAM_USER" >> /var/log/pam-markers.log
exit 0
EOF
chmod +x /usr/local/bin/pam-marker
: > /var/log/pam-markers.log
printf 'account    optional   pam_exec.so quiet /usr/local/bin/pam-marker\n' >> /etc/pam.d/sshd-tunnel
printf 'account    optional   pam_exec.so quiet /usr/local/bin/pam-marker\n' >> /etc/pam.d/sshd
printf 'account    required   pam_deny.so\n' >> /etc/pam.d/sshd

# authorized keys for AD users: root-owned so sshd StrictModes passes
install -d -m 0755 /etc/ssh/tunnel_keys
for f in /opt/tunnel_keys_src/*; do
    install -m 0644 -o root -g root "$f" "/etc/ssh/tunnel_keys/$(basename "$f")"
done

echo ">> starting sssd"
sssd -i --logger=stderr 2>/var/log/sssd-stderr.log &

echo ">> waiting for AD user lookups"
for _ in $(seq 1 90); do
    getent passwd alice >/dev/null 2>&1 && break
    sleep 2
done
getent passwd alice >/dev/null || { echo "sssd cannot resolve AD users"; cat /var/log/sssd-stderr.log; exit 1; }
echo ">> AD lookups work: $(getent passwd alice)"

echo ">> applying tunnelfw policy"
/usr/local/sbin/tunnelfw.sh apply
mkdir -p /etc/ssh/sshd_tunnel_config.d
/usr/local/sbin/tunnelfw.sh sshd-snippet > /etc/ssh/sshd_tunnel_config.d/50-groups.conf

echo ">> starting sshds (22 + 2222)"
/usr/sbin/sshd -t
/usr/sbin/sshd
# tunnel daemon runs under the sshd-tunnel name so it uses /etc/pam.d/sshd-tunnel
/usr/sbin/sshd-tunnel -t -f /etc/ssh/sshd_tunnel_config
/usr/sbin/sshd-tunnel -f /etc/ssh/sshd_tunnel_config

touch /run/bastion-ready
echo ">> bastion ready"
exec tail -f /dev/null
