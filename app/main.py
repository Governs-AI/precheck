from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from .api import router
from .storage import create_tables
from .settings import settings
import json

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
    app.include_router(router, prefix="/api")
    
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        """Handle validation errors with detailed logging"""
        # Get the request body for debugging
        try:
            body = await request.body()
            body_str = body.decode('utf-8')
            print("=" * 80)
            print("❌ REQUEST VALIDATION ERROR")
            print("=" * 80)
            print(f"URL: {request.url}")
            print(f"Method: {request.method}")
            print(f"Headers: {dict(request.headers)}")
            print(f"Body: {body_str}")
            print(f"\nValidation Errors:")
            for error in exc.errors():
                print(f"  - {error}")
            print("=" * 80)
        except Exception as e:
            print(f"Could not read request body for debugging: {e}")
        
        # Return detailed error response
        return JSONResponse(
            status_code=422,
            content={
                "detail": exc.errors(),
                "body": json.loads(body_str) if body_str else None
            }
        )
    
    return app

app = create_app()
