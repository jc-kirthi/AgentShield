"""Authentication and JWT utilities for AgentShield."""

import os
import time
from typing import Any, Dict, List, Optional
import jwt
from fastapi import Header, HTTPException, status


JWT_SECRET = os.environ.get("JWT_SECRET", "agentshield-dev-secret-key-2026-signing")
JWT_ISSUER = "agentshield-demo"


def create_token(
    sub: str,
    roles: List[str],
    expires_in_seconds: int = 8 * 3600,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """Create a demo JWT token."""
    now = int(time.time())
    payload = {
        "sub": sub,
        "roles": roles,
        "iat": now,
        "exp": now + expires_in_seconds,
        "iss": JWT_ISSUER,
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def verify_token(token: str) -> Dict[str, Any]:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            issuer=JWT_ISSUER,
            options={"require": ["sub", "roles", "exp", "iss"]},
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
        )


def require_role(authorization: Optional[str], required_roles: List[str]) -> Dict[str, Any]:
    """Verify Bearer token in header and check required roles."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format; must be Bearer <token>",
        )
    token = authorization[len("Bearer ") :].strip()
    payload = verify_token(token)
    user_roles = payload.get("roles", [])
    if not any(role in user_roles for role in required_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient permissions. Required one of: {required_roles}",
        )
    return payload
