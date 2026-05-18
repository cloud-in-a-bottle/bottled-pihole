#!/bin/bash
# OpenHost supervisor for Pi-hole.
#
# Responsibilities:
#   1. Configure Pi-hole via FTLCONF_* env vars BEFORE the upstream
#      entrypoint runs:
#        * webserver port = 127.0.0.1:8053 (loopback only -- the
#          auth-proxy is the public-facing port).
#        * webserver acl  = +127.0.0.1 -- so only requests from the
#          auth-proxy can reach the admin UI; this is defense in depth
#          since the OpenHost router already gates non-owner traffic.
#        * dns listening mode = ALL (Pi-hole is in a container; clients
#          come from the host bridge, not "local subnets" from FTL's
#          POV).
#        * webserver api password = read from
#          $OPENHOST_APP_DATA_DIR/webpassword.txt, generating it on
#          first boot (see bootstrap.py).
#   2. Run bootstrap.py to mint or read the WEBPASSWORD before the
#      upstream Pi-hole starts.
#   3. Background the upstream /usr/bin/start.sh -- it sets up FTL,
#      runs cron, and execs pihole-FTL in the foreground.
#   4. Background our auth-proxy on :8080.
#   5. wait -n: if either child exits, kill the other and exit so
#      OpenHost restarts the container.
#
# All persistent state lives under $OPENHOST_APP_DATA_DIR. The upstream
# image expects /etc/pihole (the config + DB) and /etc/dnsmasq.d (extra
# dnsmasq snippets) to be persistent, so we symlink them into the
# OpenHost-mounted volume.
set -euo pipefail

log() { printf '[start.sh] %s\n' "$*" >&2; }

# --- environment plumbing ---------------------------------------------

DATA_DIR="${OPENHOST_APP_DATA_DIR:-/data/app_data/pihole}"
PIHOLE_PERSIST="$DATA_DIR/pihole"
DNSMASQ_PERSIST="$DATA_DIR/dnsmasq.d"
PWFILE="$DATA_DIR/webpassword.txt"

ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:-localhost}"
APP_NAME="${OPENHOST_APP_NAME:-pihole}"
PUBLIC_HOST="$APP_NAME.$ZONE_DOMAIN"

mkdir -p "$DATA_DIR" "$PIHOLE_PERSIST" "$DNSMASQ_PERSIST"

# Pi-hole's upstream image hard-codes /etc/pihole + /etc/dnsmasq.d as
# persistent. Mount the OpenHost data dir at those paths via bind-style
# linking. The upstream image already copied seed files into
# /etc/pihole at build time; we copy them across on first run if our
# persistent dir is empty so the seed config + gravity DB are available.
if [[ ! -L /etc/pihole ]]; then
    if [[ -d /etc/pihole && ! -f "$PIHOLE_PERSIST/.openhost-seeded" ]]; then
        log "seeding $PIHOLE_PERSIST from /etc/pihole (first boot)"
        # cp -a preserves perms + ownership so pihole-FTL can read
        # them; the upstream image already chowned to pihole:pihole.
        cp -a /etc/pihole/. "$PIHOLE_PERSIST/" 2>/dev/null || true
        touch "$PIHOLE_PERSIST/.openhost-seeded"
    fi
    rm -rf /etc/pihole
    ln -s "$PIHOLE_PERSIST" /etc/pihole
fi
if [[ ! -L /etc/dnsmasq.d ]]; then
    if [[ -d /etc/dnsmasq.d && ! -f "$DNSMASQ_PERSIST/.openhost-seeded" ]]; then
        log "seeding $DNSMASQ_PERSIST from /etc/dnsmasq.d (first boot)"
        cp -a /etc/dnsmasq.d/. "$DNSMASQ_PERSIST/" 2>/dev/null || true
        touch "$DNSMASQ_PERSIST/.openhost-seeded"
    fi
    rm -rf /etc/dnsmasq.d
    ln -s "$DNSMASQ_PERSIST" /etc/dnsmasq.d
fi

# Make pihole user the owner of the persistent dirs so FTL can write
# its sqlite DBs etc. The upstream Dockerfile creates pihole:pihole
# with PIHOLE_UID=1000 PIHOLE_GID=1000.
chown -R pihole:pihole "$PIHOLE_PERSIST" "$DNSMASQ_PERSIST" 2>/dev/null || true

# --- mint or read the WEBPASSWORD -------------------------------------
#
# bootstrap.py writes $PWFILE (mode 0600) on first boot with a strong
# random password. On every subsequent boot it just reads it. The
# auth-proxy reads it later to mint Pi-hole API sessions for the owner.
#
# CREDENTIAL LEAK NOTE: $PWFILE contains a usable password. Anyone with
# read access to $OPENHOST_APP_DATA_DIR (e.g. file-browser with
# access_all_data=true) can exfiltrate it. This is the core trade-off
# of Pattern B1; a truly password-free design would require Pattern E
# (no SSO; user logs in once with a printed password) or upstream Pi-hole
# adding header-auth (which it does not currently support).
log "running bootstrap.py"
python3 /opt/openhost-pihole/bootstrap.py
WEBPASSWORD="$(cat "$PWFILE")"
chmod 0600 "$PWFILE"

# --- export FTLCONF_* env vars ----------------------------------------
#
# Pi-hole v6 reads any setting from FTLCONF_<section>_<key> env vars.
# These take precedence over /etc/pihole/pihole.toml, so they're the
# safest way to inject our wiring (the toml file is operator-editable
# via the admin UI; env vars are read-only from FTL's POV).

# Pi-hole's web admin port. Bind to loopback so external traffic cannot
# bypass the OpenHost router + auth-proxy. Port 8053 is arbitrary; the
# auth-proxy connects to 127.0.0.1:8053.
export FTLCONF_webserver_port='127.0.0.1:8053'

# Restrict the embedded mongoose webserver to connections from
# 127.0.0.1. The auth-proxy is the only client; defense in depth in
# case someone publishes the wrong port. Note: the pihole webserver
# already binds 127.0.0.1 above so this is redundant but cheap.
export FTLCONF_webserver_acl='+127.0.0.1,+[::1]'

# Use the OpenHost public hostname so cookies/redirects are issued
# against the right domain.
export FTLCONF_webserver_domain="$PUBLIC_HOST"

# DNS listens on all interfaces inside the container. Inside the
# container "all interfaces" is just eth0 + lo; OpenHost's host-port
# mapping then publishes 0.0.0.0:<host_port> externally.
export FTLCONF_dns_listeningMode='ALL'

# Bind DNS on port 5353 inside the container. Rootless podman cannot
# grant CAP_NET_BIND_SERVICE to unprivileged users, so FTL cannot bind
# port 53 directly. The [[ports]] mapping in openhost.toml translates
# host port -> container port 5353.
export FTLCONF_dns_port='5353'

# Set the API password from the bootstrap-generated file. This is the
# password the auth-proxy POSTs to /api/auth.
export FTLCONF_webserver_api_password="$WEBPASSWORD"

# Sensible default upstream resolvers. Operators can override via
# FTLCONF_dns_upstreams (newline-separated) at deploy time.
if [[ -z "${FTLCONF_dns_upstreams:-}" ]]; then
    export FTLCONF_dns_upstreams=$'1.1.1.1\n1.0.0.1\n8.8.8.8\n8.8.4.4'
fi

# Don't display Pi-hole's own internal pi.hole DNS records to clients
# we don't own.
export FTLCONF_dns_piholePTR='PI.HOLE'

# Disable the upstream container's TAIL_FTL_LOG noise unless explicitly
# requested -- our supervisor + the auth-proxy already produce enough
# log volume.
export TAIL_FTL_LOG="${TAIL_FTL_LOG:-1}"

log "WEBPASSWORD persisted; admin UI on http://127.0.0.1:8053; DNS on :5353"

# --- launch the upstream entrypoint + the auth-proxy ------------------

# trap before backgrounding so a SIGTERM during the small window
# between the two `&` lines doesn't orphan a child.
PIHOLE_PID=""
PROXY_PID=""
trap 'kill -TERM ${PIHOLE_PID:-} ${PROXY_PID:-} 2>/dev/null; wait' TERM INT

log "starting upstream pi-hole (delegating to /usr/bin/start.sh)"
/usr/bin/start.sh &
PIHOLE_PID=$!

log "starting auth-proxy on 0.0.0.0:8080 -> 127.0.0.1:8053"
export AUTH_PROXY_LISTEN_PORT="${AUTH_PROXY_LISTEN_PORT:-8080}"
export AUTH_PROXY_UPSTREAM_HOST="127.0.0.1"
export AUTH_PROXY_UPSTREAM_PORT="8053"
export AUTH_PROXY_PWFILE="$PWFILE"
export AUTH_PROXY_DNS_HOST="127.0.0.1"
export AUTH_PROXY_DNS_PORT="5353"
python3 /opt/openhost-pihole/auth_proxy.py &
PROXY_PID=$!

set +e
wait -n "$PIHOLE_PID" "$PROXY_PID"
EXIT_CODE=$?
set -e

log "child exited (code=$EXIT_CODE); stopping container"
kill -TERM "$PIHOLE_PID" "$PROXY_PID" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
