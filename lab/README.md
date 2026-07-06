# tunnelfw lab — a real Active Directory test bed

This directory stands up a **complete, self-contained Active Directory environment
in Docker** and uses it to prove, end to end, that [tunnelfw](../README.md) does
what it claims:

- per-AD-group egress filtering enforced by nftables (`meta skuid`),
- AD group membership resolved through SSSD and synced into the firewall,
- a tunnel-only OpenSSH daemon on port 2222 with its **own PAM service name**,
  running independently of a (stand-in) daemon on port 22,
- all of it against **real AD users and groups**, not mocks.

It is meant to be read, run, and hacked on. Everything below works on a normal
Linux workstation with Docker — no AD licence, no cloud, no RHEL subscription.

> ⚠️ This is a **test lab**, not production. It uses throwaway passwords, runs a
> Samba AD domain controller with elevated container capabilities, and exposes
> services only on a private Docker network. Do not deploy it as-is.

---

## What's in the lab

Three containers on a private network (`172.30.0.0/24`):

| Container | Image | Role | Address |
|---|---|---|---|
| `tfw-dc` | Ubuntu 24.04 + Samba | **Active Directory domain controller** — provisions realm `TUNNEL.LAB`, creates the test users and groups, serves DNS/Kerberos/LDAP. | 172.30.0.10 |
| `tfw-bastion` | Rocky Linux 9 | **The bastion under test** — `adcli join`s the domain, runs SSSD, installs tunnelfw, applies the nftables policy, and runs two sshds (22 = BoKS stand-in, 2222 = tunnel-only). | 172.30.0.20 |
| `tfw-target` | Alpine + socat | **Internal services** — a banner responder on `:80` ("HTTP-OK") and `:5432` ("DB-OK") that stand in for a web tier and a database. | 172.30.0.30 |

The domain (`TUNNEL.LAB`) is provisioned with:

| AD user | AD groups | Intended reach |
|---|---|---|
| `alice` | `dbadmins`, `tunnel-users` | target **:5432** only |
| `bob` | `webdevs`, `tunnel-users` | target **:80** only |
| `charlie` | `tunnel-users` | nothing (default-deny) |

The egress policy that ties groups to destinations lives in
[`bastion/etc-tunnelfw/`](bastion/etc-tunnelfw/): `dbadmins → tcp/172.30.0.30:5432`,
`webdevs → tcp/172.30.0.30:80`.

### Files

```
lab/
├── docker-compose.yml        # the 3 services + private network
├── run-tests.sh              # bring up the lab and run all assertions
├── dc/                       # Samba AD domain controller
│   ├── Dockerfile
│   └── entrypoint.sh         # provisions TUNNEL.LAB, creates users/groups
├── bastion/                  # the RHEL-family host under test
│   ├── Dockerfile            # sssd, adcli, nftables, openssh; authselect sssd
│   ├── entrypoint.sh         # join + sssd + tunnelfw + dual sshd + test scaffolding
│   ├── krb5.conf
│   ├── sssd.conf
│   └── etc-tunnelfw/         # the egress policy the bastion loads
├── target/                   # fake internal services
│   ├── Dockerfile
│   └── serve.sh
└── keys/                     # generated at test time (gitignored)
```

The repo root is bind-mounted read-only into the bastion at `/opt/tunnelfw`, so
the lab exercises the **actual** `tunnelfw.sh` and `sshd-tunnel-setup.sh` you see
in the project — not a copy.

---

## Prerequisites

- **Docker Engine** with the **Compose v2** plugin (`docker compose`, not the old
  `docker-compose`). Check with `docker compose version`.
- A **Linux host** (the bastion loads real nftables rules in its own network
  namespace, which needs a Linux kernel; Docker Desktop on macOS/Windows uses a
  Linux VM and generally works too).
- Elevated container capabilities are granted in `docker-compose.yml`:
  - bastion: `NET_ADMIN` (load nftables rules),
  - dc: `SYS_ADMIN` (Samba writes sysvol NT ACLs to the `security.NTACL` xattr).
- ~2 GB disk for the three images, ~1.5 GB RAM while running.
- Ports are **not** published to the host by default — everything runs on the
  private Docker network and is driven via `docker exec`. Nothing binds to your
  host's 22/2222.

No AD, no RHEL subscription, and no changes to your host firewall are required.

---

## Quick start

```bash
cd lab
./run-tests.sh
```

That single script:

1. generates a throwaway SSH keypair per test user under `keys/`;
2. `docker compose up -d --build` — builds the three images and starts them;
3. waits for the bastion to signal readiness (it provisions AD, joins the domain,
   starts SSSD, applies the firewall, and starts both sshds — first run is a few
   minutes while images build and the domain provisions);
4. runs the assertion suite and prints `RESULT: N passed, M failed`.

Exit code is 0 only if every assertion passed. The lab is **left running** so you
can poke at it (see below). Tear down with:

```bash
docker compose down -v
```

Expected result: **21 passed, 0 failed.**

---

## What the tests prove

`run-tests.sh` drives two independent probe paths so a pass really means the
policy works, not just that one layer happened to allow/deny:

- **`probe_ssh`** opens a real tunnel through the port-2222 daemon
  (`ssh -W host:port`) — exercises sshd's `PermitOpen` **and** nftables together.
- **`probe_fw`** makes a raw TCP connection as the user's UID inside the bastion
  (`docker exec -u <uid> … bash -c 'cat </dev/tcp/host/port'`) — exercises the
  nftables layer **alone**, bypassing sshd.

The 21 assertions, grouped:

1. **sshd + nftables end to end (6):** alice reaches :5432 but not :80; bob
   reaches :80 but not :5432; charlie reaches neither.
2. **nftables layer alone (5):** same allow/deny by raw per-UID connection, plus
   an unmanaged (root) connection is unaffected.
3. **default-deny counter (1):** the `counter drop` in the managed chain increments.
4. **AD membership change (2):** add alice to `webdevs` in AD
   (`samba-tool group addmembers`), `sss_cache -E`, `tunnelfw.sh sync` → alice now
   reaches :80; remove + sync → blocked again. No restart.
5. **dual-daemon coexistence (2):** the port-22 daemon still serves; interactive
   shells on 2222 are refused (`ForceCommand /bin/false`).
6. **PAM service isolation (5):** an account-phase marker shows alice's tunnel ran
   the `sshd-tunnel` PAM stack (never the shared `sshd` one); the port-22 stack is
   poisoned with `pam_deny` yet the :2222 tunnels still pass (proving the stacks
   are independent); `/etc/pam.d/sshd-tunnel` has no active `pam_boks`; and the
   version-appropriate mechanism (`PAMServiceName` directive vs `argv[0]` symlink)
   was applied for the image's OpenSSH.

---

## Exploring the running lab

After `./run-tests.sh` (or `docker compose up -d --build`), the containers stay up.

```bash
# See the firewall the bastion built, with live packet/byte counters:
docker exec tfw-bastion nft list table inet tunnelfw

# tunnelfw's own view — groups, resolved UIDs, drop counter:
docker exec tfw-bastion /usr/local/sbin/tunnelfw.sh status

# Confirm AD resolution works (identical to a real SSSD/AD host):
docker exec tfw-bastion getent group dbadmins
docker exec tfw-bastion getent passwd alice

# Which PAM service does the tunnel daemon use? (the isolation proof)
docker exec tfw-bastion cat /var/log/pam-markers.log          # sshd-tunnel:<user>
docker exec tfw-bastion cat /etc/pam.d/sshd-tunnel

# Drive a tunnel by hand, as alice, to an allowed vs a denied destination:
docker exec tfw-bastion sh -c 'ssh -p 2222 -o StrictHostKeyChecking=no \
    -i /tmp/does-not-matter -W 172.30.0.30:5432 alice@127.0.0.1' </dev/null   # (use keys/alice)

# Watch the tunnel daemon's logs:
docker exec tfw-bastion journalctl -u sshd-tunnel 2>/dev/null || \
    docker logs tfw-bastion 2>&1 | grep sshd-tunnel

# Change AD membership live and re-sync, then re-check:
docker exec tfw-dc samba-tool group addmembers webdevs charlie
docker exec tfw-bastion sh -c 'sss_cache -E && /usr/local/sbin/tunnelfw.sh sync'
docker exec tfw-bastion /usr/local/sbin/tunnelfw.sh status
```

### Extend it

- **Add a policy group:** drop a `bastion/etc-tunnelfw/groups.d/<name>.conf`
  (`match=<group>` + `allow=` lines), create the group/user in `dc/entrypoint.sh`,
  and rebuild.
- **Add a test user:** add them (and their group membership) in `dc/entrypoint.sh`,
  add a keypair line in `run-tests.sh`, and add assertions.
- **Point at different destinations:** edit the `allow=` lines and the `target`
  service in `target/serve.sh`.

---

## How it works (the interesting bits)

- **AD without a licence:** `dc/entrypoint.sh` runs `samba-tool domain provision`
  to stand up a genuine AD-compatible domain controller (Kerberos, LDAP, DNS,
  SYSVOL). The bastion joins it with `adcli join` and resolves users via
  `sssd-ad` — exactly the path a real RHEL host uses.
- **UID-based egress:** after login the user's sshd process runs as their UID, so
  nftables `meta skuid` matches their outbound (tunneled) packets. Group→UID is
  resolved with `getent` (SSSD-transparent) into per-group nftables sets; see the
  [top-level README](../README.md) for the ruleset shape.
- **Per-daemon PAM isolation:** the bastion installs the tunnel daemon under its
  own PAM service name (`sshd-tunnel`) so it never shares `/etc/pam.d/sshd`. On
  the Rocky 9 image (OpenSSH 9.9p1) that's the `PAMServiceName` directive; on an
  OpenSSH ≤ 9.7 host it's an `argv[0]` symlink. The lab's negative control
  (poisoning the port-22 stack with `pam_deny`) proves the two are independent.

## Reproducibility & determinism notes

- **Readiness** is gated on a per-container marker file (`/run/bastion-ready`),
  not on `docker compose logs`, so a re-run never races against a stale "ready"
  line from a previous container.
- **First run is slow** (image builds + domain provisioning + join). Later runs
  reuse the built images. `docker compose up -d --build` recreates the containers
  each run on Docker's containerd image store, giving a fresh domain each time.
- Generated keys live in `keys/` and are **gitignored** — they never leave your
  machine.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `bastion never became ready` | Read the dumped logs the script prints. Common: DC still provisioning (give it longer / re-run), or the join failed (check `docker logs tfw-dc`). |
| DC unhealthy | Ensure the `dc` service has `cap_add: [SYS_ADMIN]`; without it Samba fails at the sysvol NT-ACL step. |
| bastion can't load nftables | Ensure the `bastion` service has `cap_add: [NET_ADMIN]`. |
| `getent passwd alice` empty on the bastion | SSSD hasn't come up or the join failed; `docker exec tfw-bastion cat /var/log/sssd-stderr.log`. |
| Everything hangs on first run | It's building three images and provisioning AD — this legitimately takes a few minutes. Watch `docker compose logs -f`. |
| Re-run behaves oddly | `docker compose down -v` for a clean slate, then `./run-tests.sh`. |

`WERR_DNS_ERROR_RECORD_ALREADY_EXISTS` lines from `tfw-dc` are benign Samba
dynamic-DNS noise and do not indicate a failure.
