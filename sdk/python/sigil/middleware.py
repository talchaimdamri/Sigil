"""Flask and FastAPI middleware for Sigil agent authentication."""

from __future__ import annotations

from functools import wraps


def require_auth_flask(sigil):
    """Flask decorator for protected routes. Verifies JWT and sets request.agent."""
    def decorator(f):
        @wraps(f)
        async def wrapper(*args, **kwargs):
            from flask import request, jsonify
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"error": "missing_token"}), 401
            try:
                agent = await sigil.verify_jwt(auth[7:])
                request.agent = agent
            except Exception:
                return jsonify({"error": "invalid_token"}), 401
            return await f(*args, **kwargs)
        return wrapper
    return decorator


def require_auth_fastapi(sigil):
    """FastAPI dependency for protected routes. Use with Depends()."""
    async def get_agent(request):
        from fastapi import HTTPException
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing_token")
        try:
            return await sigil.verify_jwt(auth[7:])
        except Exception:
            raise HTTPException(status_code=401, detail="invalid_token")
    return get_agent
