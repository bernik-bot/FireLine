"""
Manifest signing — the integrity of the control channel.

Asymmetric on purpose: the control plane holds the PRIVATE key and signs job
manifests; agents hold only the PUBLIC key and verify. A compromised or stolen
agent therefore cannot forge a valid job — it can only verify ones the real
cloud signed. (Symmetric/HMAC would let a stolen agent mint its own jobs.)

The private key is loaded from BLACKBIRCH_SIGNING_KEY (base64) or generated and
persisted to ./control_plane_ed25519.key on first run. In production this lives
in Vault/KMS, never on disk next to the app.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

_KEY_PATH = Path(os.environ.get("BLACKBIRCH_SIGNING_KEY_PATH", "control_plane_ed25519.key"))


def _load_or_create_private_key() -> Ed25519PrivateKey:
    env = os.environ.get("BLACKBIRCH_SIGNING_KEY")
    if env:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(env))
    if _KEY_PATH.exists():
        return Ed25519PrivateKey.from_private_bytes(_KEY_PATH.read_bytes())
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    _KEY_PATH.write_bytes(raw)
    try:
        _KEY_PATH.chmod(0o600)
    except OSError:
        pass
    return key


_PRIVATE_KEY = _load_or_create_private_key()
_PUBLIC_KEY = _PRIVATE_KEY.public_key()


def canonical_bytes(manifest: dict) -> bytes:
    """Deterministic serialization so signer and verifier hash identical bytes."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()


def public_key_b64() -> str:
    raw = _PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode()


def sign(manifest: dict) -> str:
    return base64.b64encode(_PRIVATE_KEY.sign(canonical_bytes(manifest))).decode()


def verify(manifest: dict, signature_b64: str, public_key_b64_str: str | None = None) -> bool:
    """Verify a manifest signature. Agents call this with the cloud's public key."""
    try:
        if public_key_b64_str:
            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64_str))
        else:
            pub = _PUBLIC_KEY
        pub.verify(base64.b64decode(signature_b64), canonical_bytes(manifest))
        return True
    except (InvalidSignature, ValueError):
        return False
