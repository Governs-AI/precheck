from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from .api import router
from .storage import create_tables
from .settings import settings
import logging
import sys
import json

def _configure_logging() -> None:
    """Set up JSON structured logging. Debug level gated behind settings.debug."""
    level = logging.DEBUG if settings.debug else logging.INFO
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}',
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    logging.basicConfig(level=level, handlers=[handler], force=True)


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
    _configure_logging()
    app = FastAPI(
        title="GovernsAI Precheck",
        version="0.1.0",
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
