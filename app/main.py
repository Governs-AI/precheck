from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from .api import router
from .storage import create_tables
from .settings import settings
import logging
import json

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    create_tables()
    yield
    # Shutdown
    pass

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create and configure FastAPI application"""
    app = FastAPI(
        title="GovernsAI Precheck",
        version="0.0.1",
        description="Policy evaluation and PII redaction service for GovernsAI",
        lifespan=lifespan
    )
    app.include_router(router, prefix="/api")

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        """Handle validation errors — logs only field names, never header values or body content"""
        error_fields = [
            {"loc": e.get("loc"), "type": e.get("type")}
            for e in exc.errors()
        ]
        logger.warning(
            "request validation error",
            extra={"method": request.method, "path": request.url.path, "fields": error_fields},
        )
        return JSONResponse(
            status_code=422,
            content={"detail": exc.errors()},
        )

    return app

app = create_app()
