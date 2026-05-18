# OpenHost wrapper around the official pi-hole image.
#
# The upstream image is Alpine-based, runs pihole-FTL (DNS resolver +
# blocklist engine + embedded webserver) under capsh, and exposes:
#
#   - 53/tcp + 53/udp     DNS server (the user-facing service)
#   - 80/tcp              Web admin UI
#   - 443/tcp             Web admin UI (TLS, self-signed -- we ignore)
#   - 67/udp              DHCP (we don't use)
#   - 123/udp             NTP (we don't use)
#
# We add:
#
#   - python3 + tini      For the auth-proxy + supervised init.
#   - ca-certificates     So PyJWT/requests etc. work if we add Pattern D
#                         later (currently unused but cheap).
#   - bash, curl, jq      Already present in upstream image; listed for
#                         visibility.
#
# Our /usr/bin/start.sh REPLACES the upstream entrypoint. We re-exec the
# upstream start.sh from inside our supervisor so we can run the
# auth-proxy alongside it.
FROM docker.io/pihole/pihole:latest

# Avoid interactive prompts; install tini + python.
RUN apk add --no-cache python3 tini

# Drop our supervisor + auth-proxy + bootstrap into /opt/openhost-pihole.
RUN mkdir -p /opt/openhost-pihole
COPY auth_proxy.py /opt/openhost-pihole/auth_proxy.py
COPY bootstrap.py /opt/openhost-pihole/bootstrap.py
COPY start.sh     /opt/openhost-pihole/start.sh

RUN chmod 0755 \
    /opt/openhost-pihole/start.sh \
    /opt/openhost-pihole/auth_proxy.py \
    /opt/openhost-pihole/bootstrap.py

# Keep the upstream image's EXPOSE intact.  OpenHost's [[ports]] handles
# the 53 TCP+UDP mapping; the manifest's `port` field handles 8080 for
# the web admin (via the auth-proxy).
EXPOSE 5353/tcp 5353/udp 8080/tcp

# tini reaps zombies and forwards SIGTERM cleanly to start.sh, which
# supervises both the upstream pihole entrypoint and our auth-proxy via
# `wait -n`.
ENTRYPOINT ["/sbin/tini", "--", "/opt/openhost-pihole/start.sh"]
