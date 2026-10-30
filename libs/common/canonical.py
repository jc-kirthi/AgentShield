"""Canonical JSON serialization and sha256 hashing."""

import hashlib
import json
from typing import Any


def canonical_json_bytes(data: Any) -> bytes:
    """Return UTF-8 encoded canonical JSON: sorted keys, no whitespace separators."""
    return json.dumps(
        data,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_json_str(data: Any) -> str:
    """Return canonical JSON string."""
    return canonical_json_bytes(data).decode("utf-8")


def sha256_canonical(data: Any) -> str:
    """Return hex sha256 of canonical JSON."""
    return hashlib.sha256(canonical_json_bytes(data)).hexdigest()


def sha256_bytes(b: bytes) -> str:
    """Return hex sha256 of raw bytes."""
    return hashlib.sha256(b).hexdigest()
