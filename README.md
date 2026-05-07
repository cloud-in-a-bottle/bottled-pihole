# openhost-pihole

[Pi-hole](https://pi-hole.net) network-wide DNS-based ad-blocker, packaged
as an OpenHost app. Wraps the official `docker.io/pihole/pihole:latest`
image with an OpenHost auth-proxy that auto-logs the zone owner into the
admin UI, and publishes Pi-hole's DNS server on host port 53 so that user
devices (phones, laptops, routers, even your VPN) can use it as their
DNS server.

## Auth model

The Pi-hole admin UI sits behind two layers:

1. **OpenHost zone_auth** -- only zone owners can reach the admin URL at
   all. Anonymous visitors are 302'd to the parent zone's `/login` by
   the OpenHost router and never see Pi-hole.
2. **Pi-hole `sid` cookie** -- Pi-hole's own session-based auth. The
   auth-proxy mints this cookie automatically for the owner via the
   Pi-hole v6 `POST /api/auth` endpoint, using a strong WEBPASSWORD
   generated on first boot.

This is **Pattern B1** from the OpenHost SSO playbook (HTTP login dance).
Pi-hole v6 does not support trusted-header (REMOTE_USER) auth and does
not have a documentable session table on disk (sessions live in volatile
FTL memory), so neither Pattern A nor Pattern B2 is available.

### Credential leak warning

Pattern B1 requires the auth-proxy to know the WEBPASSWORD at runtime so
it can re-mint sessions after restarts. To survive container restarts
the password is persisted to:

```
$OPENHOST_APP_DATA_DIR/webpassword.txt   (mode 0600)
```

**Any other OpenHost app with `app_data = true` and
`access_all_data = true` (such as `file-browser`) will be able to
read this file.** Treat the OpenHost zone's user list as the same
trust boundary as the Pi-hole admin password.

If that's not acceptable, you have two options:

* **Pattern E (no SSO).** Delete `webpassword.txt` and `pihole -a -p` to
  set a new password by hand. The auth-proxy will fall through to
  Pi-hole's own login form, and you'll log in once with the new password.
  The browser's session cookie carries you from there.
* **Run Pi-hole on its own VM.** OpenHost is great for ad-hoc apps but
  Pi-hole is critical infrastructure and you may not want it sharing a
  trust domain with toy apps.

## Ports

| Port  | Protocol  | Where               | Purpose                                                |
|-------|-----------|---------------------|--------------------------------------------------------|
| 8080  | TCP/HTTP  | OpenHost router     | Auth-proxy → Pi-hole admin UI (gated by zone_auth)     |
| 53    | UDP + TCP | Direct (host:53)    | DNS resolver -- the user-facing service                |
| 8053  | TCP/HTTP  | Loopback only       | Pi-hole's embedded webserver; the auth-proxy upstream  |

The HTTP rail (`8080`) goes through OpenHost's reverse proxy and
inherits zone_auth. The DNS rail (`53/udp`+`53/tcp`) is published
directly on the host VM via OpenHost's `[[ports]]` mechanism and
**bypasses Caddy and zone_auth entirely** -- DNS clients have no
zone_auth credentials to present.

### Cloud firewall caveats

Most cloud VMs block UDP/53 inbound by default; you'll need to amend
the security group manually:

* **EC2 / openhost-vm-manager.** The default security group blocks all
  UDP. You'll have to amend it to allow `0.0.0.0/0:53/udp` and
  `0.0.0.0/0:53/tcp` (or restrict to your home IP). At time of writing
  this requires editing the security group via the AWS console or CLI;
  vm-manager's UI does not expose UDP rules.
* **Hetzner.** Default firewall is open; nothing to do.
* **Self-hosted (bare metal).** Make sure your home router's
  inbound-NAT rules forward 53/udp + 53/tcp to the OpenHost VM if you
  want clients on the public Internet to reach it. **You probably do
  NOT want that** -- a public Pi-hole is an open DNS resolver, ripe for
  DNS amplification abuse. Only expose 53 to networks you trust (LAN,
  WireGuard subnet, etc.).

The Pi-hole admin's status pages (`/admin/network`, the dashboard) will
reflect whichever DNS clients actually reach the box. If the cloud
firewall is blocking UDP 53, the dashboard will show no queries even
though the admin UI is reachable -- the test below diagnoses this.

## Setting it up as your DNS server

Once 53/udp is reachable, point your devices at:

```
DNS server: <openhost-host>     (e.g. pihole.andrew-1.selfhost.imbue.com or just the VM's public IP)
```

The hostname must resolve from your client device. If you point your
LAN clients at the OpenHost zone hostname, your existing DNS server
(e.g. your home router) is involved in resolving it -- a chicken-and-egg
loop if you blow away your existing DNS settings. Two ways out:

1. Use the VM's public IPv4 address directly (not the hostname).
2. On your home router, set Pi-hole as a *secondary* DNS so it falls
   back if Pi-hole becomes unreachable.

Verify resolution from a host outside your network:

```bash
dig +short google.com @pihole.andrew-1.selfhost.imbue.com
# 142.251.x.y    <- success
```

Or from inside the VM (loopback, not subject to the cloud firewall):

```bash
oh app logs pihole | head -100        # confirm FTL is up
ssh host@<openhost-host> 'dig +short google.com @127.0.0.1 -p 53'
```

## Configuration

The bootstrap supports the standard Pi-hole v6 `FTLCONF_*` env vars
(see https://docs.pi-hole.net/ftldns/configfile/). Common knobs:

| Env var                              | Default                              | Purpose                              |
|--------------------------------------|--------------------------------------|--------------------------------------|
| `FTLCONF_dns_upstreams`              | Cloudflare 1.1.1.1 + Google 8.8.8.8  | Upstream DNS servers (newline-sep)   |
| `FTLCONF_dns_dnssec`                 | `false`                              | Enable DNSSEC validation             |
| `FTLCONF_dns_listeningMode`          | `ALL`                                | Which interfaces FTL binds DNS on    |
| `TZ`                                 | (unset)                              | Timezone for log timestamps          |

These can be set via `oh app deploy --env FTLCONF_dns_dnssec=true ...`
or by editing the manifest's `[runtime.container.env]` block.

Editing in-app via the admin UI also works (Pi-hole writes
`/etc/pihole/pihole.toml` which is on the persistent volume), but
**values set via env vars override the toml file** per Pi-hole v6 rules.
If you find a setting in the admin UI is "stuck" and won't take effect,
it's because we set it via `FTLCONF_*` in `start.sh`.

## Layout

```
openhost-pihole/
  Dockerfile           # FROM docker.io/pihole/pihole:latest + python3 + tini
  openhost.toml        # port=8080 web; [[ports]] 53 for DNS
  start.sh             # bash + wait -n; runs upstream pi-hole + auth-proxy
  bootstrap.py         # one-shot: generate WEBPASSWORD, persist to data dir
  auth_proxy.py        # SSO sidecar (Pattern B1)
  README.md            # you are here
  .gitignore
```

## Verifying the SSO

```bash
TOKEN=pYkboo15U_vaS_mMCCPx9rT_ZJtJNQLuSKFiCjd5ACU
HOST=pihole.andrew-1.selfhost.imbue.com

rm -f /tmp/jar
curl -sk -H "Authorization: Bearer $TOKEN" -H "Accept: text/html" \
  -L --max-redirs 10 -c /tmp/jar -b /tmp/jar -o /tmp/r.html \
  "https://$HOST/admin/" -w 'HTTP=%{http_code}\nFINAL=%{url_effective}\n'

grep -oE '<title>[^<]+</title>' /tmp/r.html
# Expected: <title>Pi-hole - <hostname></title>     (the admin dashboard)
# NOT:      <title>Pi-hole - Login</title>
```

Anonymous visit (no Bearer token) should 302 to OpenHost `/login`:

```bash
curl -sk -o /dev/null "https://$HOST/admin/" -w 'HTTP=%{http_code}\n'
# Expected: HTTP=302 (or 307)
```

DNS resolution test:

```bash
dig +short google.com @<openhost-host> -p 53
# If this fails: cloud firewall is probably blocking UDP 53.
```

## Known limitations

* **Single-tenant by design.** Pi-hole only has one admin account.
  Anyone with OpenHost zone_auth access becomes the admin. Don't deploy
  this on a multi-tenant zone.
* **No DHCP / NTP server.** The upstream image supports both but we
  don't expose those ports (`67/udp`, `123/udp`). If you want them, add
  `[[ports]]` entries to `openhost.toml` and adjust the relevant
  `FTLCONF_dhcp_*` / `FTLCONF_ntp_*` env vars.
* **Self-signed TLS for `:443` is unused.** The OpenHost router does
  TLS termination on `:443` for the HTTP rail; Pi-hole's own self-signed
  cert never sees the public Internet. If you want DNS-over-HTTPS or
  DNS-over-TLS, you'd add another `[[ports]]` mapping for 853 and
  configure FTL accordingly.
* **Logout doesn't quite work.** The Pi-hole admin "Logout" button
  sends `DELETE /api/auth`, invalidating the SID. The next HTML
  navigation triggers our auto-login dance and silently re-mints a new
  session, so the user appears to "stay logged in". Acceptable
  trade-off; the OpenHost zone_auth gate is the real boundary.
