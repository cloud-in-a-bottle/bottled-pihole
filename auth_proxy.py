"""OpenHost auth-proxy for Pi-hole (Pattern B1: HTTP login dance).

Sits between the OpenHost router (terminating TLS, gating zone_auth)
and Pi-hole's embedded mongoose webserver on 127.0.0.1:8053.

Auth model
==========

  * Anonymous (no zone_auth)         -- Router 302's to /login on the
                                        parent zone before the request
                                        ever reaches us. We are never
                                        invoked in this case.
  * Owner, has Pi-hole "sid" cookie  -- Forward unchanged.
  * Owner, no "sid" cookie, HTML nav -- POST /api/auth with the
                                        bootstrap-generated WEBPASSWORD,
                                        capture the returned SID, echo
                                        a Set-Cookie on a 302 to the
                                        original URL.
   * /_healthz                        -- Static 200; never reaches Pi-hole.
                                         OpenHost's healthcheck polls
                                         this; Pi-hole's own / 302s
                                         anonymous visitors which would
                                         confuse the polling.
   * /dns-query (GET or POST)        -- DNS-over-HTTPS (RFC 8484).
                                         Public (no zone_auth needed).
                                         Sends the DNS wire query to
                                         Pi-hole over TCP and returns
                                         the response.

Security notes
==============

  * ``X-OpenHost-Is-Owner`` and ``X-OpenHost-User`` headers from
    inbound requests are ALWAYS stripped before being forwarded
    upstream. The OpenHost router stamps these on requests it has
    verified; if a client supplies them directly they would be a
    forgery vector.
  * The WEBPASSWORD is read from a file at proxy startup AND on
    every cache miss, so a password rotation by the operator (rm
    pwfile + restart) takes effect without rebooting the proxy.
    But: if the operator has ALREADY rotated the password by hand
    (``pihole -a -p NEWPASS``) without updating the file, the
    auth-proxy's POST will fail and we fall through to a plain
    pass-through, which lands the user on Pi-hole's own login page
    and they can sign in by hand. This is the intended failure
    mode -- never break the user's ability to log in by hand.
  * Pi-hole's session SID is bound to client IP. From Pi-hole's POV,
    every request comes from 127.0.0.1 (the auth-proxy connects
    over loopback) regardless of the actual visitor IP. So an SID
    minted from this proxy will validate on every subsequent
    request from the same proxy, which is exactly what we want.

Implementation notes
====================

  * Skeleton (BaseHTTPRequestHandler -> ThreadingHTTPServer with
    streaming body forwarding, hop-by-hop header stripping, etc.) is
    adapted from ``openhost-bookstack/auth_proxy.py`` and
    ``openhost-gemini-microblog/auth_proxy.py``.
  * Pi-hole accepts the SID via cookie ``sid=<SID>`` and the CSRF
    token via header ``X-FTL-CSRF: <CSRF>`` (or the corresponding
    cookie which the Pi-hole admin SPA reads). For navigation HTML
    requests we set both as cookies; the SPA reads them on first
    load.
  * /api/* requests are passed through with their existing
    Authorization / X-FTL-SID / cookie headers untouched. We do
    NOT auto-login on API calls; tools using the API should
    authenticate themselves.
"""

from __future__ import annotations

import base64
import http.client
import json
import logging
import os
import socket
import struct
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

OWNER_HEADER_NAME = "X-OpenHost-Is-Owner"
USER_HEADER_NAME = "X-OpenHost-User"
PIHOLE_SID_COOKIE = "sid"

# Headers we must drop before proxying the request upstream. The
# standard hop-by-hop set per RFC 7230, plus Host (we set it from
# X-Forwarded-Host) and Content-Length (we recompute).
HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        "Host",
        "Content-Length",
    )
)

# Defense in depth: never let a client inject these headers; only the
# OpenHost router is allowed to stamp them.
ALWAYS_STRIP_HEADERS = frozenset(h.lower() for h in (OWNER_HEADER_NAME, USER_HEADER_NAME))

CLIENT_READ_TIMEOUT_SECONDS = 60

# Pi-hole's web admin handles file uploads (gravity blocklist imports,
# config restores) but they are small (<50 MiB).  100 MiB body cap
# leaves comfortable headroom and matches what the bookstack reference
# uses.
MAX_BODY_BYTES = 100 * 1024 * 1024

PIHOLE_API_AUTH_PATH = "/api/auth"
HEALTHZ_PATH = "/_healthz"
DOH_PATH = "/dns-query"
DOH_CONTENT_TYPE = "application/dns-message"
DNS_TCP_TIMEOUT = 10
MAX_DNS_MESSAGE = 65535

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


def _parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    if not cookie_header:
        return {}
    result: dict[str, str] = {}
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        result.setdefault(name.strip(), value.strip())
    return result


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


def _read_password(pwfile: str) -> str | None:
    """Read the bootstrap-generated WEBPASSWORD file.

    Returns None if the file is missing or empty (auto-login then
    falls through to a plain pass-through and the user gets the
    upstream login form).
    """
    try:
        with open(pwfile, encoding="utf-8") as fh:
            value = fh.read().strip()
    except OSError as exc:
        log.warning("could not read %s: %s", pwfile, exc)
        return None
    return value or None


def _dns_query_tcp(host: str, port: int, wire: bytes) -> bytes | None:
    """Send a raw DNS query over TCP and return the response wire bytes."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(DNS_TCP_TIMEOUT)
        s.connect((host, port))
        s.sendall(struct.pack(">H", len(wire)) + wire)
        length_buf = b""
        while len(length_buf) < 2:
            chunk = s.recv(2 - len(length_buf))
            if not chunk:
                return None
            length_buf += chunk
        resp_len = struct.unpack(">H", length_buf)[0]
        if resp_len > MAX_DNS_MESSAGE:
            return None
        data = b""
        while len(data) < resp_len:
            chunk = s.recv(resp_len - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    except (OSError, struct.error) as exc:
        log.warning("DNS TCP query failed: %s", exc)
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass


def _login_to_pihole(
    upstream_host: str,
    upstream_port: int,
    password: str,
) -> tuple[str, str] | None:
    """POST /api/auth with the password; return (sid, csrf) or None.

    Pi-hole returns 200 with body::

        {"session": {"valid": true, "totp": false, "sid": "...",
                     "csrf": "...", "validity": 1800}, "took": 0.0001}

    or 401 / 429 on failure. We only care about success.
    """
    payload = json.dumps({"password": password}).encode("utf-8")
    conn = http.client.HTTPConnection(upstream_host, upstream_port, timeout=15)
    try:
        conn.request(
            "POST",
            PIHOLE_API_AUTH_PATH,
            body=payload,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(payload)),
                # Pi-hole accepts requests without a Host header on
                # loopback; set one anyway so any future Host-header
                # validation upstream works.
                "Host": f"{upstream_host}:{upstream_port}",
            },
        )
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            log.warning(
                "auto-login: POST /api/auth returned %d (expected 200); body=%r",
                resp.status,
                body[:200],
            )
            return None
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            log.warning("auto-login: malformed JSON from /api/auth: %s", exc)
            return None
        session = parsed.get("session") or {}
        if not session.get("valid"):
            log.warning("auto-login: session.valid=false in /api/auth response")
            return None
        sid = session.get("sid")
        csrf = session.get("csrf", "")
        if not isinstance(sid, str) or not sid:
            log.warning("auto-login: no SID in /api/auth response")
            return None
        if not isinstance(csrf, str):
            csrf = ""
        return sid, csrf
    except (OSError, http.client.HTTPException) as exc:
        log.warning("auto-login: HTTP error during /api/auth: %s", exc)
        return None
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


class AuthProxyHandler(BaseHTTPRequestHandler):
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 8053
    pwfile: str = "/data/app_data/pihole/webpassword.txt"
    dns_host: str = "127.0.0.1"
    dns_port: int = 5353

    # The default BaseHTTPRequestHandler.log_message goes to stderr
    # with timestamps; ours adds a slight prefix and silences the
    # healthz polling (which is high-frequency and noisy).
    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        path = getattr(self, "path", "")
        if path == HEALTHZ_PATH:
            return
        log.info("%s - " + format, self.address_string(), *args)

    # ---- HTTP method handlers ----------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch()

    def _safe_send_error(self, code: int, message: str) -> None:
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    def _serve_healthz(self) -> None:
        """Static 200 for the OpenHost healthcheck.

        We MUST NOT proxy the healthcheck to Pi-hole because Pi-hole
        302's anonymous visitors and the OpenHost healthcheck doesn't
        follow redirects -- it would treat the 302 as "not 2xx" and
        mark the app unhealthy.
        """
        body = b"ok\n"
        try:
            self.send_response(200, "OK")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError as exc:
            log.debug("client disconnected during healthz: %s", exc)

    def _serve_doh(self) -> None:
        """Handle DNS-over-HTTPS requests (RFC 8484).

        GET  /dns-query?dns=<base64url>       -> application/dns-message
        POST /dns-query  (body is raw wire)   -> application/dns-message
        """
        wire: bytes | None = None

        if self.command == "GET":
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            dns_param = params.get("dns", [None])[0]
            if not dns_param:
                self._safe_send_error(400, "missing dns parameter")
                return
            try:
                wire = base64.urlsafe_b64decode(dns_param + "==")
            except Exception:
                self._safe_send_error(400, "invalid base64url in dns parameter")
                return
        elif self.command == "POST":
            ct = self.headers.get("Content-Type", "")
            if DOH_CONTENT_TYPE not in ct.lower():
                self._safe_send_error(415, "expected application/dns-message")
                return
            cl = self.headers.get("Content-Length")
            if not cl:
                self._safe_send_error(400, "missing Content-Length")
                return
            try:
                length = int(cl)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if length < 12 or length > MAX_DNS_MESSAGE:
                self._safe_send_error(400, "invalid DNS message size")
                return
            try:
                wire = self.rfile.read(length)
            except (OSError, TimeoutError):
                self._safe_send_error(400, "read failed")
                return
        else:
            self._safe_send_error(405, "Method Not Allowed")
            return

        if not wire or len(wire) < 12:
            self._safe_send_error(400, "DNS message too short")
            return

        resp = _dns_query_tcp(self.dns_host, self.dns_port, wire)
        if resp is None:
            self._safe_send_error(502, "DNS backend error")
            return

        try:
            self.send_response(200, "OK")
            self.send_header("Content-Type", DOH_CONTENT_TYPE)
            self.send_header("Content-Length", str(len(resp)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(resp)
        except OSError as exc:
            log.debug("client disconnected during DoH response: %s", exc)

    # ---- main dispatch -----------------------------------------------

    def _dispatch(self) -> None:
        try:
            self.connection.settimeout(CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            pass

        path = self.path or "/"

        if path == HEALTHZ_PATH or path.startswith(HEALTHZ_PATH + "?"):
            self._serve_healthz()
            return

        if path == DOH_PATH or path.startswith(DOH_PATH + "?"):
            self._serve_doh()
            return

        is_owner = self.headers.get(OWNER_HEADER_NAME, "").lower() == "true"
        cookies = _parse_cookie_header(self.headers.get("Cookie"))
        has_sid = bool(cookies.get(PIHOLE_SID_COOKIE))

        accept = self.headers.get("Accept", "")
        is_html_navigation = (
            self.command == "GET" and "text/html" in accept.lower()
        )

        # Don't auto-login on:
        #   * API calls -- they carry their own auth and the response
        #     is JSON the SPA expects unmodified.
        #   * non-HTML navigations -- assets, XHRs, websockets. These
        #     would be confused by a 302.
        #   * requests that already have a sid cookie -- the user is
        #     already logged in.
        #   * non-owner requests -- the OpenHost router would have
        #     bounced them, but defense in depth: we never auto-login
        #     someone who isn't the owner.
        is_api = path.startswith("/api/")

        if (
            is_owner
            and is_html_navigation
            and not is_api
        ):
            # Auto-login when the owner has no sid cookie, OR when the
            # existing sid is expired/invalid. We validate by hitting
            # Pi-hole's /api/auth with the sid; if it comes back
            # invalid, we mint a fresh session.
            need_login = not has_sid
            if has_sid and not self._is_sid_valid(cookies.get(PIHOLE_SID_COOKIE, "")):
                need_login = True
            if need_login and self._maybe_auto_login():
                return

        self._proxy()

    def _is_sid_valid(self, sid: str) -> bool:
        """Check if a Pi-hole session ID is still valid."""
        if not sid:
            return False
        conn = http.client.HTTPConnection(
            self.upstream_host, self.upstream_port, timeout=5
        )
        try:
            conn.request(
                "GET",
                "/api/auth",
                headers={
                    "Host": f"{self.upstream_host}:{self.upstream_port}",
                    "Cookie": f"sid={sid}",
                    "X-FTL-SID": sid,
                },
            )
            resp = conn.getresponse()
            body = resp.read()
            if resp.status != 200:
                return False
            parsed = json.loads(body.decode("utf-8"))
            session = parsed.get("session") or {}
            return bool(session.get("valid"))
        except Exception:
            return False
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _maybe_auto_login(self) -> bool:
        password = _read_password(self.pwfile)
        if not password:
            log.warning(
                "auto-login: WEBPASSWORD missing/unreadable at %s; "
                "falling through to upstream login form",
                self.pwfile,
            )
            return False

        result = _login_to_pihole(self.upstream_host, self.upstream_port, password)
        if result is None:
            return False
        sid, csrf = result

        target_path = self.path or "/"
        # Open-redirect defense: never redirect to an absolute URL,
        # even if our incoming `path` somehow contains one.
        parsed = urllib.parse.urlparse(target_path)
        if parsed.scheme or parsed.netloc:
            target_path = "/"

        # Pi-hole's admin UI lives at /admin/. If the visitor
        # navigated to /, take them straight to /admin/ rather than
        # to the FTL JSON-only welcome at /.
        if target_path == "/" or target_path == "":
            target_path = "/admin/"

        try:
            self.send_response(302)
            self.send_header("Location", target_path)
            # The Pi-hole admin UI reads the SID from `sid` cookie
            # and the CSRF from the `csrf` cookie. Both are set with
            # Path=/ so they reach /api/* and /admin/ alike.
            #
            # We pass HttpOnly on the SID cookie (the SPA reads it via
            # cookie + the server reads it on every request); the
            # admin UI doesn't need JS access to the SID itself. The
            # CSRF cookie must be JS-readable so the SPA can echo it
            # in the X-FTL-CSRF header.
            self.send_header(
                "Set-Cookie",
                f"{PIHOLE_SID_COOKIE}={sid}; Path=/; HttpOnly; Secure; SameSite=Lax",
            )
            if csrf:
                self.send_header(
                    "Set-Cookie",
                    f"csrf={csrf}; Path=/; Secure; SameSite=Lax",
                )
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        except OSError as exc:
            log.debug("client disconnected during auto-login redirect: %s", exc)
            return False

        log.info(
            "auto-login: minted Pi-hole session for owner; redirected to %s",
            target_path,
        )
        return True

    def _proxy(self) -> None:
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | ALWAYS_STRIP_HEADERS,
        )
        forwarded_host = self.headers.get("X-Forwarded-Host", "").strip()
        if forwarded_host:
            cleaned_headers.append(("Host", forwarded_host))
        else:
            cleaned_headers.append(
                ("Host", f"{self.upstream_host}:{self.upstream_port}")
            )

        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower().strip()
        if transfer_encoding and transfer_encoding != "identity":
            self._safe_send_error(501, "Transfer-Encoding not supported")
            return

        body: bytes | None = None
        content_length_header = self.headers.get("Content-Length")
        if content_length_header:
            try:
                length = int(content_length_header)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if length < 0:
                self._safe_send_error(400, "negative Content-Length")
                return
            if length > MAX_BODY_BYTES:
                self._safe_send_error(413, "request body too large")
                return
            if length > 0:
                try:
                    body = self.rfile.read(length)
                except (OSError, TimeoutError) as exc:
                    log.info("client read error: %s", exc)
                    self._safe_send_error(400, "request body read failed")
                    return
                if len(body) != length:
                    self._safe_send_error(400, "incomplete request body")
                    return
            else:
                body = b""
        elif self.command in ("POST", "PUT", "PATCH", "DELETE"):
            body = b""

        conn = http.client.HTTPConnection(
            self.upstream_host, self.upstream_port, timeout=120
        )
        try:
            try:
                conn.putrequest(
                    self.command,
                    self.path,
                    skip_host=True,
                    skip_accept_encoding=True,
                )
                for key, value in cleaned_headers:
                    conn.putheader(key, value)
                if body is not None:
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body)
                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            try:
                payload = upstream.read(MAX_BODY_BYTES + 1)
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream read error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                try:
                    upstream.close()
                except Exception as close_exc:  # noqa: BLE001
                    log.debug("upstream.close() raised: %s", close_exc)
                return
            try:
                upstream.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("upstream.close() raised (ignored): %s", exc)
            if len(payload) > MAX_BODY_BYTES:
                self._safe_send_error(502, "upstream response too large")
                return

            reason = upstream.reason or ""
            try:
                self.send_response(upstream.status, reason)
                for key, value in upstream.getheaders():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
            except OSError as exc:
                log.debug("client disconnected mid-response: %s", exc)
        finally:
            conn.close()


class IPv4ThreadingServer(ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def main() -> int:
    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 8080)
        upstream_port = _port_from_env("AUTH_PROXY_UPSTREAM_PORT", 8053)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    upstream_host = os.environ.get("AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1").strip()
    pwfile = os.environ.get(
        "AUTH_PROXY_PWFILE", "/data/app_data/pihole/webpassword.txt"
    )

    try:
        dns_port = _port_from_env("AUTH_PROXY_DNS_PORT", 5353)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1
    dns_host = os.environ.get("AUTH_PROXY_DNS_HOST", "127.0.0.1").strip()

    AuthProxyHandler.upstream_host = upstream_host
    AuthProxyHandler.upstream_port = upstream_port
    AuthProxyHandler.pwfile = pwfile
    AuthProxyHandler.dns_host = dns_host
    AuthProxyHandler.dns_port = dns_port

    try:
        server = IPv4ThreadingServer(("0.0.0.0", listen_port), AuthProxyHandler)
    except OSError as exc:
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port,
            exc,
        )
        return 1
    log.info(
        "listening on 0.0.0.0:%d -> %s:%d (pwfile=%s)",
        listen_port,
        upstream_host,
        upstream_port,
        pwfile,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
