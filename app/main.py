from fastapi import FastAPI
from contextlib import asynccontextmanager
from .api import router
from .storage import create_tables
from .settings import settings

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    create_tables()
    yield
    # Shutdown
    pass

def create_app() -> FastAPI:
    """Create and configure FastAPI application"""
    app = FastAPI(
        title="GovernsAI Precheck",
        version="0.0.1",
        description="Policy evaluation and PII redaction service for GovernsAI",
        lifespan=lifespan
    )
    app.include_router(router)
    return app

app = create_app()
