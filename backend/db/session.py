"""
db/session.py — Async SQLAlchemy engine and session factory.

Usage in FastAPI:
    from db.session import get_db

    @router.get("/example")
    async def example(db: AsyncSession = Depends(get_db)):
        ...
"""
from __future__ import annotations

import os
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Database URL & Engine
# ---------------------------------------------------------------------------
DATABASE_URL: str = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:Akrithi%401234@localhost:5433/NIDS",
)

import sys
from sqlalchemy.pool import NullPool

is_testing = "pytest" in sys.modules or os.getenv("TESTING") == "1"

engine_kwargs = {
    "echo": os.getenv("LOG_LEVEL", "info").lower() == "debug",
}

if is_testing:
    engine_kwargs["poolclass"] = NullPool
else:
    engine_kwargs["pool_size"] = 10
    engine_kwargs["max_overflow"] = 20
    engine_kwargs["pool_pre_ping"] = False

engine: AsyncEngine = create_async_engine(DATABASE_URL, **engine_kwargs)


# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------
AsyncSessionLocal: sessionmaker = sessionmaker(  # type: ignore[call-overload]
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield a database session and ensure it is closed after the request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
