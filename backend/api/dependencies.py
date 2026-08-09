"""
api/dependencies.py — Shared FastAPI dependency providers.

Imported by routers to get a DB session or Redis client via Depends().
"""
from __future__ import annotations

import os
from collections.abc import AsyncGenerator

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from db.session import AsyncSessionLocal

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Redis connection pool — created once on module import, reused per request
# ---------------------------------------------------------------------------
_redis_pool: aioredis.Redis | None = None


def get_redis_url() -> str:
    """Return configured REDIS_URL or fallback to localhost."""
    return os.getenv("REDIS_URL", "redis://localhost:6379/0")


def get_redis_pool() -> aioredis.Redis:
    """Return (or lazily initialise) the shared async Redis client."""
    global _redis_pool
    import asyncio
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None

    pool_loop = getattr(_redis_pool, "_connection_loop", None)
    if _redis_pool is None or (current_loop and pool_loop != current_loop):
        redis_url = get_redis_url()
        _redis_pool = aioredis.Redis.from_url(
            redis_url, encoding="utf-8", decode_responses=True, protocol=2
        )
        _redis_pool._connection_loop = current_loop
    return _redis_pool



async def get_redis() -> aioredis.Redis:
    """FastAPI dependency — yields the shared Redis client."""
    return get_redis_pool()


# ---------------------------------------------------------------------------
# Database session dependency (re-exported from db/session.py for convenience)
# ---------------------------------------------------------------------------
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields a per-request async DB session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
