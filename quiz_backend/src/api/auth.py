"""
Supabase JWT verification utilities for FastAPI.

Supports verifying Supabase-issued access tokens using either:
1) SUPABASE_JWT_SECRET (HS256) for local/dev setups, OR
2) SUPABASE_PROJECT_URL to fetch JWKS and verify RS256 tokens.

Env vars used (configure in your deployment/.env):
- SUPABASE_PROJECT_URL: e.g. https://xxxx.supabase.co (used for JWKS)
- SUPABASE_JWT_SECRET: JWT secret (only if your project uses HS256 tokens)
- SUPABASE_JWT_AUDIENCE: optional; expected aud claim
- SUPABASE_JWT_ISSUER: optional; expected iss claim (defaults from project url)
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import httpx
import jwt
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError


@dataclass(frozen=True)
class AuthConfig:
    """Resolved authentication configuration."""
    jwt_secret: Optional[str]
    project_url: Optional[str]
    audience: Optional[str]
    issuer: Optional[str]


def _get_env(name: str) -> Optional[str]:
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    return value if value else None


# PUBLIC_INTERFACE
def get_auth_config() -> AuthConfig:
    """Load auth configuration from environment variables."""
    jwt_secret = _get_env("SUPABASE_JWT_SECRET")
    project_url = _get_env("SUPABASE_PROJECT_URL")
    audience = _get_env("SUPABASE_JWT_AUDIENCE")

    issuer = _get_env("SUPABASE_JWT_ISSUER")
    if issuer is None and project_url:
        issuer = f"{project_url.rstrip('/')}/auth/v1"

    return AuthConfig(
        jwt_secret=jwt_secret,
        project_url=project_url,
        audience=audience,
        issuer=issuer,
    )


_JWKS_CACHE: Dict[str, Tuple[PyJWKClient, float]] = {}
_JWKS_TTL_SECONDS = 60 * 10  # 10 minutes


def _get_jwks_client(project_url: str) -> PyJWKClient:
    jwks_url = f"{project_url.rstrip('/')}/auth/v1/.well-known/jwks.json"
    cached = _JWKS_CACHE.get(jwks_url)
    now = time.time()
    if cached and (now - cached[1]) < _JWKS_TTL_SECONDS:
        return cached[0]

    client = PyJWKClient(jwks_url)
    _JWKS_CACHE[jwks_url] = (client, now)
    return client


def _verify_with_secret(token: str, cfg: AuthConfig) -> Dict[str, Any]:
    options = {"verify_aud": cfg.audience is not None}
    return jwt.decode(
        token,
        cfg.jwt_secret,  # type: ignore[arg-type]
        algorithms=["HS256"],
        audience=cfg.audience,
        issuer=cfg.issuer,
        options=options,
    )


def _verify_with_jwks(token: str, cfg: AuthConfig) -> Dict[str, Any]:
    jwk_client = _get_jwks_client(cfg.project_url)  # type: ignore[arg-type]
    signing_key = jwk_client.get_signing_key_from_jwt(token)

    options = {"verify_aud": cfg.audience is not None}
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=cfg.audience,
        issuer=cfg.issuer,
        options=options,
    )


# PUBLIC_INTERFACE
def verify_supabase_jwt(token: str) -> Dict[str, Any]:
    """
    Verify a Supabase-issued JWT and return its claims.

    Raises:
        ValueError: if config is missing or the token is invalid.
    """
    cfg = get_auth_config()
    if not cfg.jwt_secret and not cfg.project_url:
        raise ValueError(
            "Missing auth configuration. Set SUPABASE_PROJECT_URL (preferred) "
            "or SUPABASE_JWT_SECRET."
        )

    try:
        # Prefer JWKS if project url is available (typical Supabase setup uses RS256).
        if cfg.project_url:
            return _verify_with_jwks(token, cfg)
        return _verify_with_secret(token, cfg)
    except InvalidTokenError as e:
        raise ValueError(f"Invalid token: {e}") from e
    except httpx.HTTPError as e:
        raise ValueError(f"Failed to fetch JWKS: {e}") from e
