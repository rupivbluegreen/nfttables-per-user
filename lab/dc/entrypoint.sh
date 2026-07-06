#!/bin/bash
# Samba AD DC for the tunnelfw lab: provisions realm TUNNEL.LAB with test
# users alice/bob/charlie in groups dbadmins/webdevs/tunnel-users.
set -euo pipefail

REALM="${REALM:-TUNNEL.LAB}"
DOMAIN="${DOMAIN:-TUNNEL}"
ADMIN_PASS="${ADMIN_PASS:?ADMIN_PASS must be set}"

if [ ! -f /var/lib/samba/private/krb5.conf ]; then
    echo ">> provisioning AD domain $REALM"
    rm -f /etc/samba/smb.conf
    samba-tool domain provision \
        --realm="$REALM" \
        --domain="$DOMAIN" \
        --server-role=dc \
        --dns-backend=SAMBA_INTERNAL \
        --adminpass="$ADMIN_PASS" \
        --option="dns forwarder=127.0.0.11"
    cp /var/lib/samba/private/krb5.conf /etc/krb5.conf

    echo ">> creating lab users and groups"
    for u in alice bob charlie; do
        samba-tool user create "$u" 'UserPass1!' --use-username-as-cn
        samba-tool user setexpiry "$u" --noexpiry
    done
    samba-tool group add dbadmins
    samba-tool group add webdevs
    samba-tool group add tunnel-users
    samba-tool group addmembers dbadmins alice
    samba-tool group addmembers webdevs bob
    samba-tool group addmembers tunnel-users alice,bob,charlie
    echo ">> provisioning complete"
fi

echo ">> starting samba"
exec samba -i
