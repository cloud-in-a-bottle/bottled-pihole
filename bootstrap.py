#!/usr/bin/env python3
"""Generate (once) and persist the Pi-hole admin password.

CREDENTIAL LEAK NOTE
====================

This script writes a usable cleartext password to
``$OPENHOST_APP_DATA_DIR/webpassword.txt`` (mode 0600). Any other
OpenHost app with ``app_data = true`` and ``access_all_data = true``
(such as file-browser) will be able to read it. This is an
unavoidable property of Pattern B1 (HTTP-driven login dance):
auth-proxy needs the password at runtime to POST /api/auth and
mint a session for the owner.

Pi-hole v6 does NOT support REMOTE_USER / trusted-header auth (no
Pattern A available), and it does NOT have an introspectable session
table (sessions live in volatile FTL memory, not on disk), so
Pattern B2 is also impossible. The remaining options are:

  * Pattern B1 (this) -- mint sessions HTTP-style; requires storing
    the password to disk so the auth-proxy can re-mint after a
    container restart.
  * Pattern E -- no SSO; the operator logs in by hand with a printed
    password and the browser's own session cookie carries them. Less
    convenient, no on-disk credential.

We ship Pattern B1 because the README explicitly trades the on-disk
credential off against one-click admin login. Operators who want
Pattern E can:

    rm $OPENHOST_APP_DATA_DIR/webpassword.txt   # NB: also rotate
    pihole -a -p                                 # set a new pw
    # ... and don't deploy the auth-proxy auto-login flow.

Generation is idempotent: if $PWFILE already exists with a
non-empty value, this script is a no-op (so a container restart
does not rotate the password and invalidate operators' active
sessions).
"""

from __future__ import annotations

import logging
import os
import secrets
import string
import sys

logging.basicConfig(
    level=logging.INFO,
    format="[bootstrap] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("bootstrap")


def main() -> int:
    data_dir = os.environ.get("OPENHOST_APP_DATA_DIR", "/data/app_data/pihole")
    pwfile = os.environ.get("AUTH_PROXY_PWFILE") or os.path.join(data_dir, "webpassword.txt")

    if not os.path.isdir(data_dir):
        try:
            os.makedirs(data_dir, mode=0o755, exist_ok=True)
        except OSError as exc:
            log.error("could not create data dir %s: %s", data_dir, exc)
            return 1

    if os.path.exists(pwfile):
        try:
            with open(pwfile, encoding="utf-8") as fh:
                existing = fh.read().strip()
        except OSError as exc:
            log.error("could not read existing %s: %s", pwfile, exc)
            return 1
        if existing:
            log.info("WEBPASSWORD already persisted at %s; skipping rotation", pwfile)
            # Make sure the perms are right even if the file pre-existed
            # from an earlier (less paranoid) deploy.
            try:
                os.chmod(pwfile, 0o600)
            except OSError:
                pass
            return 0
        log.warning("%s exists but is empty; regenerating", pwfile)

    # 32-char alphanumeric: 32 * log2(62) ~= 190 bits of entropy. Pi-hole
    # accepts arbitrary printable strings, but we avoid punctuation just
    # to dodge any shell-escaping issues if an operator ever copy-pastes
    # the file's contents into a script.
    alphabet = string.ascii_letters + string.digits
    password = "".join(secrets.choice(alphabet) for _ in range(32))

    tmp = pwfile + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(password)
        os.chmod(tmp, 0o600)
        os.replace(tmp, pwfile)
    except OSError as exc:
        log.error("could not write %s: %s", pwfile, exc)
        # Best-effort cleanup of the temp file.
        try:
            os.remove(tmp)
        except OSError:
            pass
        return 1

    log.info("generated WEBPASSWORD and persisted to %s (mode 0600)", pwfile)
    return 0


if __name__ == "__main__":
    sys.exit(main())
