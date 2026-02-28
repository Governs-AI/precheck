from app.rate_limit import RateLimiter


class FailingPipeline:
    def zremrangebyscore(self, *_args, **_kwargs):
        return self

    def zcard(self, *_args, **_kwargs):
        return self

    def zadd(self, *_args, **_kwargs):
        return self

    def expire(self, *_args, **_kwargs):
        return self

    def execute(self):
        raise RuntimeError("redis unavailable")


class FailingRedis:
    def pipeline(self):
        return FailingPipeline()


def test_in_memory_fallback_enforces_limit_without_redis():
    limiter = RateLimiter(redis_url=None)

    assert limiter.is_allowed("user-a", limit=2, window=60) is True
    assert limiter.is_allowed("user-a", limit=2, window=60) is True
    assert limiter.is_allowed("user-a", limit=2, window=60) is False


def test_in_memory_fallback_enforces_limit_when_redis_errors():
    limiter = RateLimiter(redis_url=None)
    limiter.redis_client = FailingRedis()

    assert limiter.is_allowed("user-b", limit=1, window=60) is True
    assert limiter.is_allowed("user-b", limit=1, window=60) is False


def test_in_memory_fallback_resets_after_window(monkeypatch):
    limiter = RateLimiter(redis_url=None)
    now = [1000.0]

    monkeypatch.setattr("app.rate_limit.time.time", lambda: now[0])

    assert limiter.is_allowed("user-c", limit=1, window=10) is True
    assert limiter.is_allowed("user-c", limit=1, window=10) is False

    now[0] = 1011.0
    assert limiter.is_allowed("user-c", limit=1, window=10) is True
