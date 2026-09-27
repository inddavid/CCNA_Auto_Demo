#!/usr/bin/env python3
"""
Gather SMX Device Database
============================
logs into the
SMX Northbound REST API and does a full pull of every device, replacing
the local olt_loopback_db.csv wholesale. This is the same database file
(and same location - next to this script) shared by fetch_rogue_alarm.py,
ont_ethernet_bounce.py, and populate_devices_to_clear.py.

AUTHENTICATION
---------------
The Northbound API (port 18443) accepts plain HTTP Basic Auth. For this
script's own interactive CSV pull, username/password are prompted via
getpass at runtime and only ever held in memory for that run; nothing is
written to disk that way.

Other callers (e.g. the nubare_inventory Calix loopback fallback) resolve
credentials via get_login_credentials(): SMX_USERNAME/SMX_PASSWORD env vars
first, then an encrypted credential blob embedded in this file - the same
scheme as roles/SOAKR/python/document_discovery.py, kept in sync by the
same python/update_all_soakr_dl_cred.py maintenance script.

SETUP (one-time)
-----------------
    pip install requests

USAGE
-----
    python gather_smx_database.py
        Prompts for your SMX username/password, then pulls every device
        in SMX and rebuilds olt_loopback_db.csv from scratch.

    python gather_smx_database.py --set-embedded-credentials
        Prompts for your SMX username/password and stores them encrypted
        in this file, for non-interactive callers to use.

    python gather_smx_database.py --clear-embedded-credentials
        Removes any encrypted SMX credentials embedded in this file.
"""

from __future__ import annotations

import base64
import csv
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

import requests
import urllib3
from requests.auth import HTTPBasicAuth

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SMX_HOST = "smxprod.corp.cox.com"
SMX_API_BASE = f"https://{SMX_HOST}:18443/rest/v1"
SMX_ALARM_API = f"{SMX_API_BASE}/fault/alarm"
SMX_DEVICE_API = f"{SMX_API_BASE}/config/device"

# SMX presents a self-signed cert on this port. Windows/Chrome/Bruno trust it
# via the OS certificate store, but Python's `requests` uses its own certifi
# bundle and doesn't - so verification is disabled here for this known,
# internal-only host. The InsecureRequestWarning that would otherwise print
# on every request is silenced right below.
VERIFY_SSL = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SCRIPT_DIR = Path(__file__).resolve().parent

# Local CSV "database" of device name -> IPv6 loopback - same file/location
# used by fetch_rogue_alarm.py, ont_ethernet_bounce.py, and
# populate_devices_to_clear.py.
DEVICE_DB_PATH = SCRIPT_DIR / "olt_loopback_db.csv"
DEVICE_DB_FIELDS = [
    "device_name",
    "ipv6_loopback",
    "ipv6_loopback_full",
    "model",
    "vendor",
    "last_updated",
]

# ---------------------------------------------------------------------------
# Embedded credentials (same scheme as roles/SOAKR/python/document_discovery.py,
# updated by the same python/update_all_soakr_dl_cred.py maintenance script -
# a distinct EMBEDDED_CREDENTIAL_CONTEXT keeps this derived key separate from
# the SOAKR portal one even when the same corporate username/password is used
# for both).
# ---------------------------------------------------------------------------
ENV_SMX_USERNAME = os.getenv("SMX_USERNAME", "").strip()
ENV_SMX_PASSWORD = os.getenv("SMX_PASSWORD", "")
EMBEDDED_CREDENTIAL_KEY = os.getenv("SOAKR_CREDENTIAL_KEY", "")
EMBEDDED_CREDENTIAL_VERSION = 2
EMBEDDED_CREDENTIAL_CONTEXT = "diamond/inventory_plugins/gather_smx_database.py"
# This keeps credentials out of plaintext in git, but it is still weaker than a real
# secret store because the decrypt logic lives in the same script.
# To store credentials in this file, run:
#   python3 gather_smx_database.py --set-embedded-credentials
# To update the stored password later, run the same command again and enter the new
# password when prompted. The encrypted blob below will be rewritten in place.
# Optional: set SOAKR_CREDENTIAL_KEY before running the command to bind decryption to
# an extra shared secret. If you use it, set the same value in both local and EE.
# BEGIN EMBEDDED PORTAL CREDENTIALS
EMBEDDED_PORTAL_CREDENTIALS = {
    "ciphertext": "lGqc2ajBvAxu5tDtQ7DujipCiH+8D639Gw9ycsqBGYNyjK846vBK3deppWiqHCDqUQ==",
    "mac": "F1+2QL2YsGSAzRGdpmpPUQ3Paev5jG00adBx7yarjsE=",
    "salt": "Jyvqo22MeY3fwn9NOqCM5g==",
    "version": 2
}
# END EMBEDDED PORTAL CREDENTIALS
EMPTY_EMBEDDED_PORTAL_CREDENTIALS = {
    "version": EMBEDDED_CREDENTIAL_VERSION,
    "salt": "",
    "ciphertext": "",
    "mac": "",
}
_RESOLVED_LOGIN_CREDENTIALS: Optional[Tuple[str, str, str]] = None


def portable_credential_fingerprint() -> bytes:
    parts = [EMBEDDED_CREDENTIAL_CONTEXT]
    if EMBEDDED_CREDENTIAL_KEY:
        parts.append(EMBEDDED_CREDENTIAL_KEY)
    return "|".join(parts).encode("utf-8")


def derive_embedded_credential_key(salt: bytes, fingerprint: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        fingerprint,
        salt,
        200_000,
        dklen=32,
    )


def xor_with_keystream(value: bytes, key: bytes) -> bytes:
    keystream = bytearray()
    counter = 0
    while len(keystream) < len(value):
        keystream.extend(hashlib.sha256(key + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(left ^ right for left, right in zip(value, keystream))


def encode_base64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decode_base64(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"))
    except Exception as exc:
        raise RuntimeError(
            f"Embedded credential field '{label}' is not valid base64."
        ) from exc


def encrypt_portal_credentials(username: str, password: str) -> Dict[str, str]:
    payload = json.dumps(
        {"userName": username, "password": password},
        separators=(",", ":"),
    ).encode("utf-8")
    salt = secrets.token_bytes(16)
    key = derive_embedded_credential_key(salt, portable_credential_fingerprint())
    ciphertext = xor_with_keystream(payload, key)
    mac = hmac.new(key, salt + ciphertext, hashlib.sha256).digest()
    return {
        "version": EMBEDDED_CREDENTIAL_VERSION,
        "salt": encode_base64(salt),
        "ciphertext": encode_base64(ciphertext),
        "mac": encode_base64(mac),
    }


def load_embedded_portal_credentials() -> Optional[Tuple[str, str]]:
    blob = EMBEDDED_PORTAL_CREDENTIALS
    ciphertext_value = str(blob.get("ciphertext", "")).strip()
    if not ciphertext_value:
        return None

    salt = decode_base64(str(blob.get("salt", "")), "salt")
    ciphertext = decode_base64(ciphertext_value, "ciphertext")
    stored_mac = decode_base64(str(blob.get("mac", "")), "mac")

    key = derive_embedded_credential_key(salt, portable_credential_fingerprint())
    expected_mac = hmac.new(key, salt + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_mac, expected_mac):
        raise RuntimeError(
            "Embedded SMX credentials could not be verified (MAC mismatch)."
        )

    payload = json.loads(xor_with_keystream(ciphertext, key).decode("utf-8"))
    username = str(payload.get("userName", "")).strip()
    password = str(payload.get("password", ""))
    if not username or not password:
        raise RuntimeError("Embedded SMX credentials are missing a username or password.")
    return username, password


def get_login_credentials() -> Tuple[str, str, str]:
    """Resolve SMX login credentials: env vars first, then the embedded blob."""
    global _RESOLVED_LOGIN_CREDENTIALS

    if _RESOLVED_LOGIN_CREDENTIALS is not None:
        return _RESOLVED_LOGIN_CREDENTIALS

    if ENV_SMX_USERNAME and ENV_SMX_PASSWORD:
        _RESOLVED_LOGIN_CREDENTIALS = (ENV_SMX_USERNAME, ENV_SMX_PASSWORD, "environment")
        return _RESOLVED_LOGIN_CREDENTIALS

    embedded_credentials = load_embedded_portal_credentials()
    if embedded_credentials is not None:
        _RESOLVED_LOGIN_CREDENTIALS = (
            embedded_credentials[0],
            embedded_credentials[1],
            "embedded",
        )
        return _RESOLVED_LOGIN_CREDENTIALS

    _RESOLVED_LOGIN_CREDENTIALS = ("", "", "")
    return _RESOLVED_LOGIN_CREDENTIALS


def update_embedded_credentials_blob(blob: Dict[str, str]) -> None:
    source_path = Path(__file__).resolve()
    source_text = source_path.read_text(encoding="utf-8")
    replacement = (
        "# BEGIN EMBEDDED PORTAL CREDENTIALS\n"
        f"EMBEDDED_PORTAL_CREDENTIALS = {json.dumps(blob, indent=4, sort_keys=True)}\n"
        "# END EMBEDDED PORTAL CREDENTIALS"
    )
    pattern = re.compile(
        r"# BEGIN EMBEDDED PORTAL CREDENTIALS\n"
        r"EMBEDDED_PORTAL_CREDENTIALS = .*?\n"
        r"# END EMBEDDED PORTAL CREDENTIALS",
        re.S,
    )
    updated_source, replacements = pattern.subn(replacement, source_text, count=1)
    if replacements != 1:
        raise RuntimeError("Could not find the embedded credential block to update.")
    source_path.write_text(updated_source, encoding="utf-8")


def prompt_and_store_embedded_credentials() -> None:
    username = input("SMX username: ").strip()
    if not username:
        raise ValueError("SMX username cannot be empty.")

    password = getpass.getpass("SMX password: ")
    confirm_password = getpass.getpass("Confirm SMX password: ")
    if not password:
        raise ValueError("SMX password cannot be empty.")
    if password != confirm_password:
        raise ValueError("SMX password confirmation did not match.")

    update_embedded_credentials_blob(encrypt_portal_credentials(username, password))
    print(f"Embedded credentials updated in {Path(__file__).resolve()}")
    if EMBEDDED_CREDENTIAL_KEY:
        print("SOAKR_CREDENTIAL_KEY was included in the encryption key derivation.")


def clear_embedded_credentials() -> None:
    update_embedded_credentials_blob(EMPTY_EMBEDDED_PORTAL_CREDENTIALS)
    print(f"Embedded credentials cleared in {Path(__file__).resolve()}")


class SMXAuthError(RuntimeError):
    """Raised when SMX rejects the supplied credentials."""


class SMXClient:
    """Thin client for talking to the SMX Northbound REST API over Basic Auth."""

    def __init__(self, api_base: str = SMX_API_BASE, verify_ssl: bool = VERIFY_SSL):
        self.api_base = api_base
        self.verify_ssl = verify_ssl
        self.session: requests.Session | None = None

    # -- Auth -----------------------------------------------------------
    def login(self, username: str, password: str) -> None:
        """Set up a Basic Auth session and verify the credentials work."""
        session = requests.Session()
        session.auth = HTTPBasicAuth(username, password)
        session.verify = self.verify_ssl

        # Fail fast with a clear message if the credentials are wrong,
        # rather than surfacing a confusing error later during the pull.
        # `verify` is also passed explicitly here (not just set on the
        # session) because some locked-down corporate Python installs have
        # an SSL-inspection hook that only honors a per-call `verify` kwarg.
        resp = session.get(
            SMX_ALARM_API, params={"offset": 0, "limit": 1}, timeout=30, verify=self.verify_ssl
        )
        if resp.status_code in (401, 403):
            raise SMXAuthError(f"SMX rejected those credentials (HTTP {resp.status_code}).")
        resp.raise_for_status()

        self.session = session

    def _require_session(self) -> requests.Session:
        if self.session is None:
            raise SMXAuthError("Not logged in yet - call login() first.")
        return self.session

    # -- Devices / loopbacks ------------------------------------------------
    def get_all_devices(self, page_size: int = 500):
        """Page through the *entire* /config/device list, unfiltered."""
        session = self._require_session()
        devices = []
        offset = 0
        while True:
            resp = session.get(
                SMX_DEVICE_API,
                params={"offset": offset, "limit": page_size},
                timeout=60,
                verify=self.verify_ssl,
            )
            resp.raise_for_status()
            page = resp.json() or []
            if not page:
                break
            devices.extend(page)
            if len(page) < page_size:
                break
            offset += page_size

        return devices


def login_with_resolved_credentials(client: "SMXClient" | None = None) -> "SMXClient":
    """Log in using get_login_credentials() (env vars, then embedded blob).

    Raises SMXAuthError if no credentials are available or SMX rejects them.
    Used by callers (like the nubare_inventory PON/Calix loopback fallback)
    that need a logged-in client without any interactive prompt.
    """
    username, password, _source = get_login_credentials()
    if not username or not password:
        raise SMXAuthError(
            "No SMX credentials available (set SMX_USERNAME/SMX_PASSWORD or run "
            "'python3 gather_smx_database.py --set-embedded-credentials')."
        )
    client = client or SMXClient()
    client.login(username, password)
    return client


def get_device_loopback_map(client: "SMXClient") -> dict[str, dict[str, str]]:
    """Pull every device from SMX and return an in-memory map only - no CSV.

    Keyed by the device's own hostname, upper-cased, to
    {"ipv6_loopback": ..., "ipv6_loopback_full": ..., "model": ..., "vendor": ...}.
    """
    devices = client.get_all_devices()
    loopback_map: dict[str, dict[str, str]] = {}
    for device in devices:
        name = device.get("hostname")
        if not name:
            continue
        loopback_map[str(name).strip().upper()] = {
            "ipv6_loopback": device.get("address2") or "",
            "ipv6_loopback_full": device.get("address") or "",
            "model": device.get("model") or "",
            "vendor": device.get("vendor") or "",
        }
    return loopback_map


# ---------------------------------------------------------------------------
# Local OLT loopback database (CSV next to this script)
# ---------------------------------------------------------------------------
def save_device_db(db: dict, path: Path = DEVICE_DB_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=DEVICE_DB_FIELDS)
        writer.writeheader()
        for name in sorted(db):
            row = db[name]
            writer.writerow({field: row.get(field, "") for field in DEVICE_DB_FIELDS})


def populate_full_device_db(client: SMXClient) -> dict:
    """One-time (or occasional) full pull of every device in SMX, replacing
    the local loopback database wholesale.
    """
    print("Pulling the full device list from SMX (this can take a little while)...")
    devices = client.get_all_devices()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db = {}
    skipped = 0
    for device in devices:
        name = device.get("hostname")
        if not name:
            skipped += 1
            continue
        db[name] = {
            "device_name": name,
            "ipv6_loopback": device.get("address2") or "",
            "ipv6_loopback_full": device.get("address") or "",
            "model": device.get("model") or "",
            "vendor": device.get("vendor") or "",
            "last_updated": now,
        }

    save_device_db(db)
    note = f" ({skipped} skipped, no hostname)" if skipped else ""
    print(f"Populated {len(db)} device(s) into {DEVICE_DB_PATH}{note}")
    return db


def main():
    if "--set-embedded-credentials" in sys.argv[1:]:
        prompt_and_store_embedded_credentials()
        return
    if "--clear-embedded-credentials" in sys.argv[1:]:
        clear_embedded_credentials()
        return

    print("Gather SMX Device Database")
    print("-" * 40)
    username = input("SMX username: ").strip()
    password = getpass.getpass("SMX password: ")

    client = SMXClient()

    print("\nLogging in to SMX...")
    try:
        client.login(username, password)
    except SMXAuthError as exc:
        print(f"Authentication failed: {exc}")
        sys.exit(1)
    finally:
        # Don't linger on the credentials any longer than necessary.
        del password

    populate_full_device_db(client)


if __name__ == "__main__":
    main()