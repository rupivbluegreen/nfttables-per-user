# Runbook: second OpenSSH (port 2222) alongside BoKS on RHEL 9, with its own PAM service

**Summary — the answer.** Yes: a second, tunnel-only OpenSSH daemon on port 2222 can run **fully independently** of the BoKS‑managed sshd on port 22, by giving it its **own PAM service name** (`sshd-tunnel` → `/etc/pam.d/sshd-tunnel`) whose stack contains **no `pam_boks`**. The two daemons then share no PAM state. The one subtlety that trips people up: **how OpenSSH selects its PAM service name is version‑specific.** Just copying the config and changing `Port` is *not* enough — that daemon still reads `/etc/pam.d/sshd`.

| RHEL 9 minor | OpenSSH | PAM service name comes from | How to select `sshd-tunnel` |
|---|---|---|---|
| 9.0 – 9.7 | 8.7p1 | `argv[0]` basename (no directive exists) | **symlink**: run the daemon as `/usr/sbin/sshd-tunnel` (symlink → `sshd`), by **absolute path** |
| 9.8+ (and current Rocky / CentOS Stream 9) | 9.9p1 | `PAMServiceName` directive (`argv[0]` ignored) | **directive**: `PAMServiceName sshd-tunnel` in the tunnel config |

BoKS keeps port 22 through its own `boks_sshd` fork and by default does **not** own `/etc/pam.d/sshd` (it is not in BoKS's `sysreplace.conf` `pamdir` list), so a distinctly named `/etc/pam.d/sshd-tunnel` will not collide with anything BoKS manages — **as long as you do not add it to `sysreplace.conf`**.

The installer script `sshd-tunnel-setup.sh` auto‑detects the version and applies the correct mechanism, so the recommended path is simply to run it (Step 3). Manual equivalents are given for operators who want to do each step by hand.

---

## 1. Preconditions

```bash
# RHEL 9 host, BoKS managing sshd on port 22 (leave it alone).
cat /etc/redhat-release
ssh -V                                  # note the OpenSSH version (see table above)

# SSSD joined to AD and resolving the tunnel group's members:
getent group <tunnel-group>             # must list your AD members
getent passwd <an-ad-user>              # must resolve

# The tunnelfw repo checked out on the host (contains tunnelfw.sh, sshd-tunnel-setup.sh, sshd/, systemd/).
```

If `getent group` does not return the AD members, fix NSS/SSSD first — `tunnelfw.sh` resolves group membership with `getent`, so nothing downstream works until this does.

## 2. Confirm which PAM mechanism applies

```bash
ssh -V                                                    # e.g. OpenSSH_8.7p1 or OpenSSH_9.9p1
./sshd-tunnel-setup.sh --print-mechanism "$(ssh -V 2>&1)" # prints: symlink | directive
./sshd-tunnel-setup.sh --self-test                        # sanity-checks the version logic
```

- `symlink` → OpenSSH ≤ 9.7 (RHEL 9.0–9.7). The daemon must be launched under the name `sshd-tunnel`.
- `directive` → OpenSSH ≥ 9.8 (RHEL 9.8+, current Rocky/Stream 9). A `PAMServiceName` directive selects the service.

## 3. Install (recommended: the setup script does the version‑correct thing)

```bash
sudo ./sshd-tunnel-setup.sh
```

This is idempotent and performs:

- creates the symlink `/usr/sbin/sshd-tunnel → /usr/sbin/sshd` (always; load‑bearing on ≤ 9.7);
- installs `/etc/ssh/sshd_tunnel_config` and creates `/etc/ssh/sshd_tunnel_config.d/`;
- installs `/etc/pam.d/sshd-tunnel` — **no `pam_boks`** (see Step 3b);
- on OpenSSH ≥ 9.8 only, writes `/etc/ssh/sshd_tunnel_config.d/00-pamservice.conf` containing `PAMServiceName sshd-tunnel` (it is an unknown keyword on 8.7p1 and would fail `sshd -t`, so it is omitted there);
- best‑effort SELinux port label (`semanage`, see Step 4);
- validates with `sshd-tunnel -t -f /etc/ssh/sshd_tunnel_config`.

### 3a. Manual equivalent

**OpenSSH ≤ 9.7 (symlink):**
```bash
sudo ln -sfn /usr/sbin/sshd /usr/sbin/sshd-tunnel
sudo install -m 0644 sshd/sshd_tunnel_config /etc/ssh/sshd_tunnel_config
sudo install -d -m 0755 /etc/ssh/sshd_tunnel_config.d
# DO NOT add a PAMServiceName directive on 8.7p1 — the binary name provides the service.
```

**OpenSSH ≥ 9.8 (directive):**
```bash
sudo ln -sfn /usr/sbin/sshd /usr/sbin/sshd-tunnel   # cosmetic here; keeps ExecStart uniform
sudo install -m 0644 sshd/sshd_tunnel_config /etc/ssh/sshd_tunnel_config
sudo install -d -m 0755 /etc/ssh/sshd_tunnel_config.d
printf 'PAMServiceName sshd-tunnel\n' | sudo tee /etc/ssh/sshd_tunnel_config.d/00-pamservice.conf
```

### 3b. The PAM stack `/etc/pam.d/sshd-tunnel`

Pubkey‑only daemon, so sshd never runs the PAM *auth* phase; *account* + *session* run under `UsePAM yes`. It contains **no `pam_boks`**, which is what keeps port 2222 independent of BoKS:

```
auth       required   pam_deny.so
account    required   pam_sss.so
password   required   pam_deny.so
session    required   pam_limits.so
session    optional   pam_sss.so
session    optional   pam_mkhomedir.so umask=0077
```

> Alternative: set `UsePAM no` in the tunnel config and skip PAM entirely — even simpler, but then `pam_mkhomedir`/`pam_sss` session hooks don't run, so pre‑create home directories out of band.

## 4. SELinux and firewalld

```bash
sudo semanage port -a -t ssh_port_t -p tcp 2222     # or -m if already defined
sudo firewall-cmd --permanent --add-port=2222/tcp
sudo firewall-cmd --reload
```

The nftables `tunnelfw` table lives in the `output` hook and coexists with firewalld (which polices `input`/`forward`).

## 5. Authorized keys for AD users

```bash
sudo install -d -m 0755 /etc/ssh/tunnel_keys
# one file per AD user, root-owned so StrictModes passes:
sudo install -m 0644 <user>.pub /etc/ssh/tunnel_keys/<user>
```

`AuthorizedKeysFile /etc/ssh/tunnel_keys/%u` means users need no home directory present before first login and cannot self‑manage keys.

## 6. Apply the egress policy and generate the sshd snippet

```bash
sudo install -m 0755 tunnelfw.sh /usr/local/sbin/tunnelfw.sh
sudo install -d -m 0755 /etc/tunnelfw/groups.d
sudo install -m 0644 config/tunnelfw.conf /etc/tunnelfw/
sudo install -m 0644 config/groups.d/*.conf /etc/tunnelfw/groups.d/

sudo /usr/local/sbin/tunnelfw.sh apply                 # load the nftables ruleset
sudo /usr/local/sbin/tunnelfw.sh sshd-snippet > /etc/ssh/sshd_tunnel_config.d/50-groups.conf
sudo /usr/local/sbin/tunnelfw.sh status                # sanity check

sudo install -m 0644 systemd/*.service systemd/*.timer /etc/systemd/system/
sudo systemctl enable --now tunnelfw.service
sudo systemctl enable --now tunnelfw-sync.timer        # re-syncs AD membership every 5 min
```

## 7. Start the tunnel daemon

```bash
sudo /usr/sbin/sshd-tunnel -t -f /etc/ssh/sshd_tunnel_config   # validate
sudo systemctl enable --now sshd-tunnel.service
systemctl status sshd-tunnel.service
ss -ltnp 'sport = :2222'                                        # confirm it is listening
```

## 8. BoKS coexistence verification (do these on the real host)

```bash
# 1. Ensure BoKS will NOT manage/overwrite our PAM file:
grep -n sshd-tunnel /etc/opt/boksm/sysreplace.conf || echo "good: not BoKS-managed"

# 2. Confirm BoKS keeps port 22 via its own daemon and hasn't taken /etc/pam.d/sshd:
ps -ef | grep -E 'boks_sshd|sshd' | grep -v grep
systemctl status sshd 2>/dev/null                 # BoKS may run its own unit

# 3. NSS still resolves AD users (needed by tunnelfw.sh getent):
getent group <tunnel-group>
```

- Do **not** add `sshd-tunnel` to `sysreplace.conf` — leaving it out is what keeps BoKS's activate/deactivate cycle from touching it.
- Port 2222 is deliberately **outside** BoKS access routes and audit. Get the BoKS owner's sign‑off, and confirm BoKS is not configured to detect/kill a foreign sshd.
- RHEL system‑wide crypto policy still applies to the second daemon; confirm it meets any FIPS/hardening BoKS requires.

## 9. Smoke test

```bash
# As an AD user with a key installed, open a tunnel to an ALLOWED destination:
ssh -p 2222 -N -L 15432:<db-host>:5432 <ad-user>@<bastion> &
curl -sv telnet://127.0.0.1:15432        # or your db client — should connect

# A destination NOT in the user's group policy should be refused/dropped:
ssh -p 2222 -N -L 18080:<disallowed>:80 <ad-user>@<bastion>   # forward fails / hangs

# Confirm the tunnel used the sshd-tunnel PAM service, not sshd. Watch the log while
# connecting (journal shows pam_unix/pam_sss entries tagged with the service name):
journalctl -u sshd-tunnel -f
# and verify the account stack in effect:
sudo grep -H pam_boks /etc/pam.d/sshd-tunnel && echo "PROBLEM: pam_boks present" || echo "good: no pam_boks"
```

Expected: allowed destination connects; disallowed one is blocked at the sshd `PermitOpen` layer and/or dropped by nftables; the tunnel daemon's PAM activity references `sshd-tunnel`.

## 10. Rollback

```bash
sudo systemctl disable --now sshd-tunnel.service
sudo systemctl disable --now tunnelfw-sync.timer tunnelfw.service
sudo /usr/local/sbin/tunnelfw.sh flush            # remove the nftables table only
sudo rm -f /usr/sbin/sshd-tunnel \
           /etc/ssh/sshd_tunnel_config \
           /etc/ssh/sshd_tunnel_config.d/00-pamservice.conf \
           /etc/pam.d/sshd-tunnel
sudo semanage port -d -t ssh_port_t -p tcp 2222 || true
sudo firewall-cmd --permanent --remove-port=2222/tcp && sudo firewall-cmd --reload
```

BoKS on port 22 is never touched by any step here, so rollback cannot affect it.
