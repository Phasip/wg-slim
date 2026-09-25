"""WireGuard utility functions.

This module contains helper functions for WireGuard operations
like key generation and config section parsing.
"""

import base64
import binascii
import hashlib
import io
import os
import secrets
from typing import Dict, Iterator, Tuple

import pyqrcode


# List of known WireGuard keys in canonical casing
KNOWN_WG_KEYS = {
    k.lower(): k
    for k in [
        "Address",
        "PrivateKey",
        "ListenPort",
        "DNS",
        "MTU",
        "PostUp",
        "PostDown",
        "SaveConfig",
        "Table",
        "PublicKey",
        "PresharedKey",
        "AllowedIPs",
        "Endpoint",
        "PersistentKeepalive",
    ]
}


class WgSectionSyntaxError(ValueError):
    """Raised when a WireGuard config section contains a line that is not `Key = Value`."""


"""
A case-insensitive dictionary for WireGuard config keys.
We do not limit keys to known WireGuard config keys.
We try to correct the case for known keys when iterating."""


class WireguardDict:
    def __init__(self, dict: Dict[str, str] | None = None) -> None:
        if dict is None:
            self.data = {}
        else:
            self.data: Dict[str, str] = {k.lower(): v for k, v in dict.items()}

    def __getitem__(self, key: str) -> str:
        return self.data[key.lower()]

    def __setitem__(self, key: str, value: str) -> None:
        self.data[key.lower()] = value

    def items(self) -> Iterator[Tuple[str, str]]:
        for k, v in self.data.items():
            if k in KNOWN_WG_KEYS:
                k = KNOWN_WG_KEYS[k]

            yield (k, v)

    def get(self, key: str, default: str | None = None) -> str | None:
        """Dict-style get with case-insensitive key lookup."""
        return self.data.get(key.lower(), default)

    def __delitem__(self, key: str) -> None:
        del self.data[key.lower()]

    def __contains__(self, key: str) -> bool:
        # Without this, `in` falls back to __iter__, which only case-corrects
        # keys listed in KNOWN_WG_KEYS - so `"FwMark" in d` would miss a stored
        # `fwmark`.
        return key.lower() in self.data

    def copy(self) -> "WireguardDict":
        d = WireguardDict()
        d.data = self.data.copy()
        return d

    def __iter__(self):
        for k, _ in self.items():
            yield k


def parse_wg_section(section: str) -> WireguardDict:
    """Parse a WireGuard config section (interface/as_peer) into key-value pairs.

    Returned keys are normalized to lowercase.
    """
    result = WireguardDict()
    for line in section.splitlines():
        if line.strip().startswith("#") or not line.strip():
            continue
        # TODO: Keep comments in the WireguardDict somehow
        if "=" not in line:
            raise WgSectionSyntaxError(f"Expected 'Key = Value', got {line.strip()!r}")
        k, v = line.split("=", 1)
        result[k.strip()] = v.strip()
    return result


def build_wg_section(values: WireguardDict) -> str:
    """Build a WireGuard config section from key-value pairs.

    Known WireGuard keys will be emitted with canonical casing (e.g. "PrivateKey").
    If a key is not recognized, the original key name is used.
    """
    lines: list[str] = []
    for k, v in values.items():
        lines.append(f"{k} = {v}")
    return "\n".join(lines)


def parse_bind_addr(bind_addr: str) -> Tuple[str, int]:
    """Parse bind_addr into (host, port).

    Supported formats:
    - "5000" -> ("0.0.0.0", 5000)
    - ":5000" -> ("0.0.0.0", 5000)
    - "0.0.0.0:5000" -> ("0.0.0.0", 5000)
    - "127.0.0.1:8080" -> ("127.0.0.1", 8080)
    """
    bind_addr = str(bind_addr)
    if ":" in bind_addr:
        host, port_str = bind_addr.rsplit(":", 1)
        host = host if host else "0.0.0.0"
        return host, int(port_str)
    return "0.0.0.0", int(bind_addr)


def generate_random_password(length=16) -> str:
    """Return a random password of specified length."""
    return secrets.token_urlsafe(length)[:length]


def secure_strcmp(a: str, b: str) -> bool:
    """Compare two strings in a timing-attack resistant manner."""
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# scrypt cost for new password hashes (~50ms, 16 MiB). Verification uses the
# parameters stored in the hash, so these can be raised without breaking
# existing hashes.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 256 * 1024 * 1024


def hash_password(password: str) -> str:
    """Return a `scrypt$N$r$p$salt$hash` string for `basic.password_hash`."""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=SCRYPT_MAXMEM)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def _parse_password_hash(password_hash: str) -> Tuple[int, int, int, bytes, bytes]:
    parts = password_hash.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        raise ValueError("password_hash must look like scrypt$N$r$p$salt$hash")
    try:
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = base64.b64decode(parts[4], validate=True)
        digest = base64.b64decode(parts[5], validate=True)
    except (ValueError, binascii.Error) as e:
        raise ValueError(f"password_hash is malformed: {e}") from None
    if n < 2 or n & (n - 1) or 128 * n * r > SCRYPT_MAXMEM or not salt or not digest:
        raise ValueError("password_hash has invalid scrypt parameters")
    return n, r, p, salt, digest


def validate_password_hash(password_hash: str) -> None:
    """Raise ValueError unless `password_hash` is a hash `verify_password` can check."""
    _parse_password_hash(password_hash)


def verify_password(password: str, password_hash: str) -> bool:
    """Check `password` against a `hash_password` string in constant time."""
    n, r, p, salt, digest = _parse_password_hash(password_hash)
    candidate = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=SCRYPT_MAXMEM, dklen=len(digest))
    return secrets.compare_digest(candidate, digest)


def render_qrcode_png(content: str) -> bytes:
    """Render `content` as a PNG QR code."""
    buf = io.BytesIO()
    pyqrcode.create(content).png(buf, scale=6)  # type: ignore
    return buf.getvalue()


def log_file_path(config_file_path: str) -> str:
    """Return the path of the logfile that sits next to the config file."""
    return os.path.join(os.path.dirname(config_file_path), "logs.log")
