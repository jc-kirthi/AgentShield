"""Shared request validation for ERP write endpoints."""

from typing import Any, Optional
from fastapi import HTTPException, status


def require_str(payload: dict, *keys: str, field: Optional[str] = None) -> str:
    value = None
    for key in keys:
        if key in payload and payload[key] is not None:
            value = payload[key]
            break
    name = field or keys[0]
    if value is None or (isinstance(value, str) and not value.strip()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing required field: {name}",
        )
    if not isinstance(value, (str, int)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid type for {name}: expected string",
        )
    return str(value).strip()


def require_int(payload: dict, *keys: str, field: Optional[str] = None, min_value: Optional[int] = 0) -> int:
    value: Any = None
    found = False
    for key in keys:
        if key in payload and payload[key] is not None:
            value = payload[key]
            found = True
            break
    name = field or keys[0]
    if not found:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing required field: {name}",
        )
    if isinstance(value, bool) or not isinstance(value, int):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid type for {name}: expected integer INR rupees",
        )
    if min_value is not None and value < min_value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid value for {name}: must be >= {min_value}",
        )
    return value
