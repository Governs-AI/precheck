#!/usr/bin/env python3
"""
Startup script for GovernsAI Precheck service
"""
import uvicorn
import os
from app.settings import settings

if __name__ == "__main__":
    # Ensure CWD is the repo root so relative paths (policy files, etc.) resolve correctly
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    # Parse host and port from APP_BIND
    host, port = settings.app_bind.split(":")
    port = int(port)
    
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=settings.debug,
        log_level="info" if not settings.debug else "debug"
    )
