#Test1
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api.routes import router
from app.core.config import settings
from app.db.session import engine, async_session_factory
from sqlalchemy import text


from app.db.base import Base
from app.models.secret import Secret, SecretEvent  # noqa: F401

logger = logging.getLogger("vaultdrop")

# How often to run expired-secret cleanup (seconds)
CLEANUP_INTERVAL = 3600  # 1 hour


async def _periodic_cleanup():
    """Background task that periodically deletes expired/destroyed secrets."""
    from app.services.secret_service import cleanup_expired_secrets

    while True:
        await asyncio.sleep(CLEANUP_INTERVAL)
        try:
            async with async_session_factory() as session:
                count = await cleanup_expired_secrets(session)
                if count > 0:
                    logger.info(f"Cleaned up {count} expired/destroyed secrets")
        except Exception as exc:
            logger.warning(f"Cleanup task error: {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-create tables if they don't exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Attempt to add new columns for upgrades (silently ignores if they exist on Postgres)
        if engine.dialect.name == "postgresql":
            for col_def in [
                "max_views INTEGER DEFAULT 100",
                "view_count INTEGER DEFAULT 0",
                "file_name VARCHAR(255)",
                "file_size INTEGER",
                "file_type VARCHAR(100)",
                "creator_token VARCHAR(64)",
                "failed_attempts INTEGER DEFAULT 0",
                "last_accessed_at TIMESTAMP WITH TIME ZONE",
                "is_locked BOOLEAN DEFAULT FALSE",
                "access_attempt_count INTEGER DEFAULT 0",
                "successful_view_count INTEGER DEFAULT 0",
                "has_suspicious_activity BOOLEAN DEFAULT FALSE",
                "suspicious_reason TEXT",
                "device_binding_hash VARCHAR(64)",
                "last_client_env VARCHAR(100)",
            ]:
                try:
                    await conn.execute(text(f"ALTER TABLE secrets ADD COLUMN IF NOT EXISTS {col_def}"))
                except Exception as e:
                    logger.debug(f"Column {col_def.split()[0]} error: {e}")

    # Start periodic cleanup background task
    cleanup_task = asyncio.create_task(_periodic_cleanup())

    yield

    # Cancel cleanup and dispose engine on shutdown
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
    await engine.dispose()


app = FastAPI(
    title="VaultDrop",
    description="Secure temporary information sharing",
    version="0.3.0",
    lifespan=lifespan,
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
)

# CORS — only allow configured origins, never wildcard in prod
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add security headers to every response."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all so we never leak stack traces to users."""
    logger.exception("Unhandled exception:")
    response = JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": f"{type(exc).__name__}: {str(exc)}"},
    )
    # Fix FastAPI/Starlette CORS bug on unhandled exceptions
    origin = request.headers.get("origin")
    if origin and (origin in settings.cors_origins_list or not settings.is_production):
        response.headers["access-control-allow-origin"] = origin
        response.headers["access-control-allow-credentials"] = "true"
    return response


app.include_router(router)
