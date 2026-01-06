from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.api.auth import get_auth_config, verify_supabase_jwt

openapi_tags = [
    {"name": "Health", "description": "Service liveness and readiness endpoints."},
    {"name": "Auth", "description": "Authentication helper endpoints (Supabase JWT)."},
    {"name": "Dashboard", "description": "Example protected routes for dashboard flows."},
]

app = FastAPI(
    title="QuizMaster Backend API",
    description=(
        "FastAPI backend for the QuizMaster platform.\n\n"
        "Auth: Send `Authorization: Bearer <supabase_access_token>` to protected endpoints.\n"
        "Tokens are verified using either SUPABASE_PROJECT_URL (JWKS / RS256) or SUPABASE_JWT_SECRET (HS256)."
    ),
    version="0.1.0",
    openapi_tags=openapi_tags,
)


def _parse_csv_env(name: str) -> Optional[List[str]]:
    val = os.getenv(name)
    if not val:
        return None
    parts = [p.strip() for p in val.split(",")]
    parts = [p for p in parts if p]
    return parts if parts else None


def _get_cors_origins() -> List[str]:
    """
    Determine allowed CORS origins from env.

    Uses:
    - BACKEND_CORS_ORIGINS: comma-separated list of allowed origins (preferred)
    - REACT_APP_FRONTEND_URL: fallback single origin
    - otherwise: [] (no origins allowed)
    """
    origins = _parse_csv_env("BACKEND_CORS_ORIGINS")
    if origins:
        return origins

    frontend_origin = os.getenv("REACT_APP_FRONTEND_URL")
    if frontend_origin:
        return [frontend_origin.strip()]

    return []


allowed_origins = _get_cors_origins()

# If no origins are configured, we still add CORSMiddleware but with empty origins.
# This avoids accidental permissive "*" in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AuthenticatedUser(BaseModel):
    """User information extracted from a verified JWT."""
    sub: str = Field(..., description="User ID (subject) from JWT.")
    email: Optional[str] = Field(None, description="Email from JWT claims, if present.")
    role: Optional[str] = Field(None, description="Supabase role claim, if present.")
    aud: Optional[Any] = Field(None, description="Audience claim (string or list).")
    iss: Optional[str] = Field(None, description="Issuer claim.")
    exp: Optional[int] = Field(None, description="Expiration timestamp (epoch seconds).")
    iat: Optional[int] = Field(None, description="Issued-at timestamp (epoch seconds).")
    raw_claims: Dict[str, Any] = Field(..., description="Full decoded JWT claims.")


# PUBLIC_INTERFACE
def get_current_user(authorization: Optional[str] = Header(default=None)) -> AuthenticatedUser:
    """
    FastAPI dependency: verify `Authorization: Bearer <token>` and return user claims.

    Returns:
        AuthenticatedUser derived from the JWT claims.

    Raises:
        401 if missing/invalid token, or if auth config is missing.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Expected: Bearer <token>",
        )

    token = parts[1].strip()

    try:
        claims = verify_supabase_jwt(token)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        ) from e

    sub = claims.get("sub")
    if not sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing required 'sub' claim",
        )

    return AuthenticatedUser(
        sub=sub,
        email=claims.get("email"),
        role=claims.get("role"),
        aud=claims.get("aud"),
        iss=claims.get("iss"),
        exp=claims.get("exp"),
        iat=claims.get("iat"),
        raw_claims=claims,
    )


@app.get("/", tags=["Health"], summary="Health Check", operation_id="health_check")
def health_check():
    """Health check endpoint used by platform monitoring."""
    return {"message": "Healthy"}


@app.get(
    "/auth/config",
    tags=["Auth"],
    summary="Auth config status (non-sensitive)",
    operation_id="auth_config_status",
)
def auth_config_status():
    """
    Returns whether auth verification is configured (without leaking secrets).

    Useful for diagnosing environments where JWT verification is failing because
    required env vars are missing.
    """
    cfg = get_auth_config()
    return {
        "configured": bool(cfg.jwt_secret or cfg.project_url),
        "using": "jwks" if cfg.project_url else ("secret" if cfg.jwt_secret else "none"),
        "issuer": cfg.issuer,
        "audience_configured": bool(cfg.audience),
        "cors_allowed_origins": allowed_origins,
        "missing_env_hints": [
            "SUPABASE_PROJECT_URL (preferred) or SUPABASE_JWT_SECRET",
            "BACKEND_CORS_ORIGINS or REACT_APP_FRONTEND_URL (for browser access)",
        ],
    }


@app.get(
    "/auth/me",
    tags=["Auth"],
    summary="Get current authenticated user",
    operation_id="auth_me",
)
def auth_me(user: AuthenticatedUser = Depends(get_current_user)):
    """
    Return the authenticated user profile based on JWT claims.

    Note: for now this returns token-derived claims only (no DB lookup).
    """
    return user.model_dump(exclude={"raw_claims": False})


@app.get(
    "/dashboard/summary",
    tags=["Dashboard"],
    summary="Protected dashboard summary (placeholder)",
    operation_id="dashboard_summary",
)
def dashboard_summary(user: AuthenticatedUser = Depends(get_current_user)):
    """
    Minimal protected endpoint to validate the auth flow end-to-end.

    Frontend should call this with `Authorization: Bearer <token>`.
    """
    return {
        "message": "You are authenticated and can access dashboard routes.",
        "user_id": user.sub,
        "email": user.email,
    }
