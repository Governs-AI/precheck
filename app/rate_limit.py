import redis
import logging
import time
from typing import Optional
from .settings import settings

logger = logging.getLogger(__name__)

class RateLimiter:
    """Redis-based token bucket rate limiter"""
    
    def __init__(self, redis_url: Optional[str] = None):
        self.redis_client = None
        if redis_url:
            try:
                self.redis_client = redis.from_url(redis_url)
                # Test connection
                self.redis_client.ping()
            except Exception as e:
                logger.warning("Failed to connect to Redis: %s", type(e).__name__)
                self.redis_client = None
    
    def is_allowed(self, key: str, limit: int, window: int) -> bool:
        """
        Check if request is allowed using sliding window counter
        
        Args:
            key: Unique identifier for the rate limit (e.g., user_id)
            limit: Maximum number of requests allowed
            window: Time window in seconds
        
        Returns:
            True if request is allowed, False otherwise
        """
        if not self.redis_client:
            # No Redis available, allow all requests
            return True
        
        try:
            current_time = int(time.time())
            window_start = current_time - window
            
            # Use Redis pipeline for atomic operations
            pipe = self.redis_client.pipeline()
            
            # Remove old entries
            pipe.zremrangebyscore(key, 0, window_start)
            
            # Count current requests
            pipe.zcard(key)
            
            # Add current request
            pipe.zadd(key, {str(current_time): current_time})
            
            # Set expiration
            pipe.expire(key, window)
            
            results = pipe.execute()
            current_count = results[1]
            
            return current_count < limit
            
        except Exception as e:
            logger.warning("Rate limiting error: %s", type(e).__name__)
            # Fail open - allow request if Redis is down
            return True

# Global rate limiter instance
rate_limiter = RateLimiter(settings.redis_url)
