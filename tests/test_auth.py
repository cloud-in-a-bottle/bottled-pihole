import base64
import struct
import time
from urllib.parse import urlparse

import requests
from openhost_test_harness import OpenhostStack

HTML = {"Accept": "text/html"}


def test_owner_is_logged_into_admin_ui(stack: OpenhostStack, admin_session: requests.Session) -> None:
    """The owner opening the app lands in Pi-hole's admin dashboard, not its password form (see admin_session)."""
    session, sid = admin_session, admin_session.cookies["sid"]
    auth = session.get(f"{stack.url}/api/auth", headers={"X-FTL-SID": sid}, timeout=30)
    assert auth.status_code == 200, f"GET /api/auth with the minted sid: {auth.status_code}: {auth.text[:500]}"
    assert auth.json()["session"]["valid"] is True, f"minted sid is not a valid Pi-hole session: {auth.text[:500]}"


def _dns_query(name: str, query_id: int) -> bytes:
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", 1, 1)


def test_anonymous_access(stack: OpenhostStack) -> None:
    """Anonymous visitors can't reach the admin UI or API, but the health check and DNS-over-HTTPS are public."""
    for path in ("/admin/", "/api/auth"):
        response = requests.get(f"{stack.url}{path}", headers=HTML, allow_redirects=False, timeout=30)
        location = urlparse(response.headers.get("Location", ""))
        to_router_login = location.netloc == urlparse(stack.router_url).netloc and location.path == "/login"
        assert response.status_code in (302, 303, 307) and to_router_login, (
            f"anonymous GET {path}: expected a redirect to the router login, got {response.status_code} "
            f"Location={response.headers.get('Location')!r}: {response.text[:300]}"
        )

    healthz = requests.get(f"{stack.url}/_healthz", timeout=30)
    assert healthz.status_code == 200 and healthz.text == "ok\n", f"anonymous /_healthz: {healthz.status_code}"

    query_id = 0x4F48
    wire = base64.urlsafe_b64encode(_dns_query("pi.hole", query_id)).rstrip(b"=").decode()
    deadline = time.monotonic() + 60
    while True:
        doh = requests.get(
            f"{stack.url}/dns-query", params={"dns": wire}, headers={"Accept": "application/dns-message"}, timeout=30
        )
        if doh.status_code == 200 or time.monotonic() > deadline:
            break
        time.sleep(3)
    assert doh.status_code == 200, f"anonymous DoH GET /dns-query: {doh.status_code}: {doh.text[:300]}"
    assert doh.headers["Content-Type"] == "application/dns-message", doh.headers
    response_id, flags = struct.unpack(">HH", doh.content[:4])
    assert response_id == query_id and flags & 0x8000, f"not a DNS response to our query: {doh.content[:32]!r}"
