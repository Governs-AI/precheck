#!/usr/bin/env python3
"""
Simple script to run the GovernsAI Precheck service
"""
import uvicorn
from app.settings import settings

if __name__ == "__main__":
    # Parse host and port from APP_BIND
    host, port = settings.app_bind.split(":")
    port = int(port)
    
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=settings.debug,
        log_level="info"
    )
