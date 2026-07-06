# tunnelfw — per-AD-group egress policy for an SSH tunneling bastion

Turn a RHEL 9 host into an SSH tunneling bastion where each **Active Directory
group** gets its own outbound firewall policy. AD users connect to a dedicated
OpenSSH daemon on port 2222 and open `ssh -L` / `ssh -D` tunnels; what each user
may reach is decided by the AD groups they belong to.

Enforcement is layered:

1. **nftables** (authoritative) — outbound packets are matched by the socket
   owner's UID (`meta skuid`). Group→UID membership is resolved with `getent`,
   which reads the same NSS path SSSD serves, so AD groups work with no
   AD-specific code. Users in the managed scope with no matching policy are
   **default-denied**.
2. **sshd** (defense in depth) — generated `Match Group` / `PermitOpen` blocks
   restrict tunnel destinations at the SSH layer too, so disallowed forwards
   fail fast with a clear "administratively prohibited" message instead of
   silently hanging on a dropped packet.

Why UID matching: after authentication, the per-session `sshd` process runs as
the user, so every tunneled connection carries that user's UID. `meta skgid`
is **not** used — AD group memberships are supplementary groups (the primary
group is usually "Domain Users"), which packet socket GID matching can't see.

## Repository layout

| Path | Purpose |
|------|---------|
| `tunnelfw.sh` | The CLI. Generates and loads the nftables ruleset, syncs membership, emits the sshd snippet. |
| `sshd-tunnel-setup.sh` | Version-aware installer for the tunnel daemon's own PAM service (`sshd-tunnel`): symlink on OpenSSH ≤ 9.7, `PAMServiceName` directive on ≥ 9.8. |
| `config/tunnelfw.conf` | Global config: DNS resolvers, scope groups. |
| `config/groups.d/*.conf` | One file per policy: `match=<group>` + `allow=` lines. |
| `sshd/sshd_tunnel_config` | Tunnel-only OpenSSH daemon config for port 2222. |
| `sshd/pam.d/sshd-tunnel` | PAM stack for the tunnel daemon — no `pam_boks`, so port 2222 is independent of BoKS. |
| `systemd/` | `tunnelfw.service` (apply at boot), `tunnelfw-sync.timer` (periodic membership sync), `sshd-tunnel.service` (the second daemon). |
| `docs/rhel9-boks-second-sshd-runbook.md` | Operator runbook for the RHEL 9 + BoKS deployment. |
| `lab/` | Self-contained Docker test lab: **real** Samba AD DC + SSSD-joined Rocky 9 bastion + target, with an end-to-end test suite (proves per-daemon PAM isolation). See [`lab/README.md`](lab/README.md) for a full run-it-yourself how-to. |

## How the nftables policy is built

`tunnelfw.sh apply` emits one dedicated table, loaded atomically. It never
touches other tables (firewalld's, Docker's, etc.):

```
table inet tunnelfw {
    set managed_uids { type uid; }                       # who default-deny applies to
    set resolvers4   { type ipv4_addr; }                 # allowed DNS servers
    set g_dbadmins_uid { type uid; }                     # members of "dbadmins"
    set g_dbadmins_tcp { type ipv4_addr . inet_service; flags interval; }

    chain pol_dbadmins {                                 # one per group
        ip daddr . tcp dport @g_dbadmins_tcp accept
        ip daddr . udp dport @g_dbadmins_udp accept
    }
    chain managed {
        ct state established,related accept
        oifname "lo" accept
        ip daddr @resolvers4 udp dport 53 accept         # tunnel hostnames resolve here
        ip daddr @resolvers4 tcp dport 53 accept
        meta skuid @g_dbadmins_uid jump pol_dbadmins     # multi-group users get the union
        counter drop                                     # default-deny (+ drop visibility)
    }
    chain output {
        type filter hook output priority filter; policy accept;
        meta skuid @managed_uids jump managed            # everyone else untouched
    }
}
```

A user in several groups falls through each `jump` and gets the **union** of
their groups' allow rules.

## CLI

```
tunnelfw.sh apply         # build + atomically load the full ruleset
tunnelfw.sh sync          # refresh UID sets only (for the timer; needs prior apply)
tunnelfw.sh check         # dry-run: print resolved members + validate the ruleset
tunnelfw.sh status        # groups, live UID sets, and the default-deny drop counter
tunnelfw.sh sshd-snippet  # emit Match Group blocks for the tunnel sshd
tunnelfw.sh flush         # delete the tunnelfw table (panic button; nothing else touched)
```

### Config format

`config/tunnelfw.conf`:
```
resolvers=10.0.0.2 10.0.0.3     # optional; defaults to /etc/resolv.conf nameservers
scope_groups=tunnel-users       # members are managed (default-denied) even with no policy
```

`config/groups.d/dbadmins.conf`:
```
match=dbadmins                  # exact `getent group` name (see SSSD naming below)
allow=tcp/10.1.2.0/24:5432      # proto/(IPv4 or CIDR):port-or-range
allow=tcp/10.9.0.10:22
```

`match` must equal what `getent group <name>` returns on the host. With SSSD's
`use_fully_qualified_names = True` that is `dbadmins@corp.example.com`; with it
`False` it is just `dbadmins`. `case_sensitive` matters too.

## Deploying on RHEL 9

### 1. Install

```bash
install -m 0755 tunnelfw.sh /usr/local/sbin/tunnelfw.sh
install -d -m 0755 /etc/tunnelfw/groups.d
install -m 0644 config/tunnelfw.conf /etc/tunnelfw/
install -m 0644 config/groups.d/*.conf /etc/tunnelfw/groups.d/
install -m 0644 systemd/*.service systemd/*.timer /etc/systemd/system/
```

### 2. Second OpenSSH daemon on port 2222 (own PAM service, independent of BoKS)

Feasible and standard on RHEL 9 — a second `sshd` runs from its own config and
unit alongside the primary daemon on 22. `sshd-tunnel-setup.sh` installs it with
its **own PAM service name** (`sshd-tunnel`) so it does not share BoKS's
`/etc/pam.d/sshd`; it auto-detects the OpenSSH version and applies the correct
mechanism (symlink on ≤ 9.7, `PAMServiceName` directive on ≥ 9.8). Full details
and manual steps: [`docs/rhel9-boks-second-sshd-runbook.md`](docs/rhel9-boks-second-sshd-runbook.md).

```bash
./sshd-tunnel-setup.sh --self-test          # sanity-check version detection
sudo ./sshd-tunnel-setup.sh                 # symlink + config + /etc/pam.d/sshd-tunnel + drop-in + SELinux + validate

# Open the port (firewalld shown; the tunnelfw table lives in the output hook and
# coexists with firewalld, which polices input/forward):
sudo firewall-cmd --permanent --add-port=2222/tcp && sudo firewall-cmd --reload

sudo tunnelfw.sh sshd-snippet > /etc/ssh/sshd_tunnel_config.d/50-groups.conf
sudo systemctl enable --now sshd-tunnel.service
```

Public keys for AD users go in `/etc/ssh/tunnel_keys/<username>` (root-owned;
`AuthorizedKeysFile` points there so users need no home directory to be present
before first login and cannot self-manage keys).

### 3. Enable the firewall policy

```bash
systemctl enable --now tunnelfw.service        # applies at boot
systemctl enable --now tunnelfw-sync.timer     # re-syncs AD membership every 5 min
tunnelfw.sh status                             # verify
```

## ⚠️ BoKS coexistence checklist (verify on the real host)

The target host is BoKS-managed. The tunnel daemon on 2222 runs **independently**
of BoKS by using its own PAM service name — see the full walkthrough in
[`docs/rhel9-boks-second-sshd-runbook.md`](docs/rhel9-boks-second-sshd-runbook.md).
Confirm each item on the actual host:

1. **Give the tunnel daemon its own PAM service name (version-specific).** The
   two daemons must not share `/etc/pam.d/sshd`. How OpenSSH selects its PAM
   service name differs by version, and just changing `Port` is **not** enough —
   the daemon would still read `/etc/pam.d/sshd`:
   - **OpenSSH ≤ 9.7 (RHEL 9.0–9.7):** the service name is the binary's `argv[0]`
     basename; there is no directive. Run the daemon as `/usr/sbin/sshd-tunnel`
     (a symlink to `sshd`) by absolute path so it reads `/etc/pam.d/sshd-tunnel`.
   - **OpenSSH ≥ 9.8 (RHEL 9.8+, current Rocky/Stream 9):** `argv[0]` is ignored;
     add the directive `PAMServiceName sshd-tunnel` to the tunnel config.
   `sshd-tunnel-setup.sh` auto-detects the version and applies the right one, and
   installs `/etc/pam.d/sshd-tunnel` with **no `pam_boks`** — so BoKS never gates
   2222. (The lab proves the PAM-service-name isolation; only the BoKS-specific
   items below can't be exercised there.)
2. **Don't let BoKS manage the file.** BoKS keeps port 22 via its own `boks_sshd`
   fork and by default does not own `/etc/pam.d/sshd`. Confirm `sshd-tunnel` is
   **not** listed in `/etc/opt/boksm/sysreplace.conf`, so BoKS's activate/deactivate
   cycle won't overwrite it.
3. **NSS resolution.** AD users must resolve via nsswitch (SSSD and/or BoKS) —
   `tunnelfw.sh` relies on `getent group <tunnel-group>` returning the members.
4. **Audit / access-route bypass.** Port 2222 sidesteps BoKS access routes and
   session logging by design. Get the BoKS owner's sign-off, and confirm BoKS
   isn't configured to detect or kill a foreign `sshd`.
5. **Crypto policy.** RHEL 9's system-wide crypto policy applies to the second
   daemon too; make sure it satisfies whatever FIPS/hardening BoKS requires.
6. **No port collision.** BoKS keeps port 22; the second daemon uses 2222 and a
   separate `PidFile` (`/run/sshd_tunnel.pid`). Verify nothing else claims 2222.

## Testing: the Docker AD lab

`lab/` stands up a **real** Active Directory environment — a Samba AD DC, a
Rocky 9 bastion that actually `adcli join`s the domain and resolves users
through SSSD, and a target host — then verifies enforcement end to end.

```bash
cd lab
./run-tests.sh                 # builds images, brings up the lab, runs assertions
docker compose down -v         # tear down
```

Domain `TUNNEL.LAB` with:

| User | AD groups | May tunnel to |
|------|-----------|---------------|
| alice | dbadmins, tunnel-users | target **:5432** only |
| bob | webdevs, tunnel-users | target **:80** only |
| charlie | tunnel-users | nothing (default-deny) |

The suite asserts, over real `ssh -W` tunnels through port 2222 **and** over raw
per-UID firewall probes: each user reaches only their group's port; cross-group
and no-policy destinations are blocked; the default-deny drop counter
increments; unmanaged (system) traffic is unaffected; an AD membership change
(`samba-tool group addmembers` + `tunnelfw.sh sync`) takes effect without a
restart; the port-22 daemon keeps serving; and interactive shells on 2222 are
refused. Requires Docker with `NET_ADMIN` for the bastion and `SYS_ADMIN` for
the DC (Samba writes sysvol NT ACLs to the `security.NTACL` xattr).

## Limitations

- **Egress only.** UID matching applies to locally generated (outbound) traffic.
  Return traffic is allowed via conntrack (`ct state established,related`). You
  cannot filter *inbound* connections by user this way — not a limitation for a
  tunneling bastion, where the tunnels are outbound from the host.
- **Membership changes affect new connections.** Already-established tunnels stay
  up until closed (conntrack). `-R` remote forwards are a listen-side concern —
  constrain them with `PermitListen`.
- **IPv4 destinations in v1.** Port-only matching already covers IPv6; IPv6
  destination sets are a small future addition.
- **Policy specs are IPs/CIDRs**, not hostnames (hostnames would need
  resolve-at-apply-time). `PermitOpen` cannot express CIDRs, so groups with CIDR
  policies get `PermitOpen any` at the sshd layer with nftables enforcing the
  range.
