# bottled-pihole

[Pi-hole](https://pi-hole.net) network-wide DNS-based ad-blocker, packaged
as a Cloud in a Bottle app. Wraps the official `docker.io/pihole/pihole:latest`
image with a Cloud in a Bottle auth-proxy that auto-logs the zone owner into the
admin UI, and publishes Pi-hole's DNS server on host port 53 so that user
devices (phones, laptops, routers, even your VPN) can use it as their
DNS server.

## Auth model

The Pi-hole admin UI sits behind two layers:

1. **Cloud in a Bottle zone_auth** -- only zone owners can reach the admin URL at
   all. Anonymous visitors are 302'd to the parent zone's `/login` by
   the Cloud in a Bottle router and never see Pi-hole.
2. **Pi-hole `sid` cookie** -- Pi-hole's own session-based auth. The
   auth-proxy mints this cookie automatically for the owner via the
   Pi-hole v6 `POST /api/auth` endpoint, using a strong WEBPASSWORD
   generated on first boot.

This is **Pattern B1** from the Cloud in a Bottle SSO playbook (HTTP login dance).
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

**Any other Cloud in a Bottle app with `app_data = true` and
`access_all_data = true` (such as `file-browser`) will be able to
read this file.** Treat the Cloud in a Bottle zone's user list as the same
trust boundary as the Pi-hole admin password.

If that's not acceptable, you have two options:

* **Pattern E (no SSO).** Delete `webpassword.txt` and `pihole -a -p` to
  set a new password by hand. The auth-proxy will fall through to
  Pi-hole's own login form, and you'll log in once with the new password.
  The browser's session cookie carries you from there.
* **Run Pi-hole on its own VM.** Cloud in a Bottle is great for ad-hoc apps but
  Pi-hole is critical infrastructure and you may not want it sharing a
  trust domain with toy apps.

## Ports

| Port  | Protocol  | Where               | Purpose                                                |
|-------|-----------|---------------------|--------------------------------------------------------|
| 8080  | TCP/HTTP  | Cloud in a Bottle router     | Auth-proxy → Pi-hole admin UI (gated by zone_auth)     |
| 8080  | TCP/HTTPS | Cloud in a Bottle router     | DoH endpoint at `/dns-query` (public, no auth needed)  |
| 5353  | UDP + TCP | Direct (host:5353)  | DNS resolver -- the user-facing service                |
| 8053  | TCP/HTTP  | Loopback only       | Pi-hole's embedded webserver; the auth-proxy upstream  |

The HTTP rail (`8080`) goes through Cloud in a Bottle's reverse proxy and
inherits zone_auth. The DNS rail (`5353/udp`+`5353/tcp`) is published
directly on the host VM via Cloud in a Bottle's `[[ports]]` mechanism and
**bypasses Caddy and zone_auth entirely** -- DNS clients have no
zone_auth credentials to present.

The default host port is **5353** instead of the standard 53 because
Cloud in a Bottle runs CoreDNS on port 53 for zone-authoritative DNS and ACME
DNS-01 certificate challenges. If CoreDNS is disabled on your instance,
edit `openhost.toml` and set `host_port = 53` for the standard port.
Clients must specify the port explicitly: `dig @<host> -p 5353 example.com`.

### Cloud firewall caveats

Most cloud VMs block non-standard UDP ports inbound by default; you'll
need to amend the security group manually:

* **EC2 / openhost-vm-manager.** The default security group blocks all
  UDP. You'll have to amend it to allow `0.0.0.0/0:5353/udp` and
  `0.0.0.0/0:5353/tcp` (or restrict to your home IP). At time of
  writing this requires editing the security group via the AWS console
  or CLI; vm-manager's UI does not expose UDP rules.
* **Hetzner.** Default firewall is open; nothing to do.
* **Self-hosted (bare metal).** Make sure your home router's
  inbound-NAT rules forward the DNS port to the Cloud in a Bottle VM if you
  want clients on the public Internet to reach it. **You probably do
  NOT want that** -- a public Pi-hole is an open DNS resolver, ripe for
  DNS amplification abuse. Only expose DNS to networks you trust (LAN,
  WireGuard subnet, etc.).

The Pi-hole admin's status pages (`/admin/network`, the dashboard) will
reflect whichever DNS clients actually reach the box. If the cloud
firewall is blocking the DNS port, the dashboard will show no queries even
though the admin UI is reachable -- the test below diagnoses this.

## DNS-over-HTTPS (DoH)

The auth-proxy serves a standard RFC 8484 DoH endpoint at `/dns-query`.
This path is public (no zone_auth required) so browsers and OS-level
DoH clients can use it directly. TLS is handled by the Cloud in a Bottle router
(Caddy).

**Brave / Chrome / Edge / Firefox secure DNS URL:**

```
https://pihole.andrew-1.selfhost.imbue.com/dns-query
```

In Brave: Settings → Privacy and security → Security → Use secure DNS →
With Custom → paste the URL above.

Verify from the command line:

```bash
curl -sk "https://pihole.<zone>/dns-query?dns=AAABAAABAAAAAAAAB2dvb2dsZQNjb20AAAEAAQ" \
  -H "Accept: application/dns-message" -o - | xxd | head
```

## Setting it up as your DNS server

Once the DNS port is reachable, point your devices at:

```
DNS server: <openhost-host>     (e.g. the VM's public IP)
DNS port:   5353                (non-standard; some clients don't support custom ports)
```

The default port is 5353. Clients must specify it explicitly. Not all
devices support custom DNS ports; for those, you'll need to either
disable CoreDNS and change `host_port` to 53, or use a DNS forwarder
on your LAN that proxies standard port 53 to the Pi-hole's 5353.

Verify resolution:

```bash
dig +short google.com @<openhost-host> -p 5353
# 142.251.x.y    <- success
```

Or from inside the VM (loopback, not subject to the cloud firewall):

```bash
oh app logs pihole | head -100        # confirm FTL is up
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
bottled-pihole/
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

Anonymous visit (no Bearer token) should 302 to Cloud in a Bottle `/login`:

```bash
curl -sk -o /dev/null "https://$HOST/admin/" -w 'HTTP=%{http_code}\n'
# Expected: HTTP=302 (or 307)
```

DNS resolution test:

```bash
dig +short google.com @<openhost-host> -p 5353
# If this fails: cloud firewall is probably blocking UDP 5353.
```

## Known limitations

* **DNS on non-standard port (5353).** Cloud in a Bottle's CoreDNS occupies
  port 53 for zone-authoritative DNS and ACME DNS-01 challenges.
  Pi-hole defaults to host port 5353 to avoid the conflict. Not all
  client devices support custom DNS ports. To use standard port 53,
  disable CoreDNS on your instance and edit `openhost.toml`.
* **Single-tenant by design.** Pi-hole only has one admin account.
  Anyone with Cloud in a Bottle zone_auth access becomes the admin. Don't deploy
  this on a multi-tenant zone.
* **No DHCP / NTP server.** The upstream image supports both but we
  don't expose those ports (`67/udp`, `123/udp`). If you want them, add
  `[[ports]]` entries to `openhost.toml` and adjust the relevant
  `FTLCONF_dhcp_*` / `FTLCONF_ntp_*` env vars.
* **No DNS-over-TLS (DoT).** DoH is supported via `/dns-query` (see
  above). DoT on port 853 is not currently exposed. If you need it,
  add a `[[ports]]` entry for 853 and configure FTL accordingly.
* **Logout doesn't quite work.** The Pi-hole admin "Logout" button
  sends `DELETE /api/auth`, invalidating the SID. The next HTML
  navigation triggers our auto-login dance and silently re-mints a new
  session, so the user appears to "stay logged in". Acceptable
  trade-off; the Cloud in a Bottle zone_auth gate is the real boundary.

## License

Pi-hole is licensed under the European Union Public Licence v. 1.2 (EUPL-1.2).
The Cloud in a Bottle packaging files in this repository are MIT-licensed. See
`LICENSE` and `NOTICE` for details.
