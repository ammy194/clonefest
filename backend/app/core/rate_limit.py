import time
from collections import defaultdict
from fastapi import HTTPException, Request, status


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = window_seconds
        self.requests: dict[str, list[float]] = defaultdict(list)
        self.enabled = True

    def _get_client_key(self, request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def check(self, request: Request) -> None:
        if not self.enabled:
            return

        key = self._get_client_key(request)
        now = time.time()
        cutoff = now - self.window

        # Filter expired timestamps
        self.requests[key] = [t for t in self.requests[key] if t > cutoff]

        # Prune empty keys to prevent unbounded memory growth (Bug 4 fix)
        if not self.requests[key]:
            del self.requests[key]

        if len(self.requests.get(key, [])) >= self.max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please slow down.",
            )

        self.requests[key].append(now)

    def reset(self) -> None:
        self.requests.clear()


create_limiter = RateLimiter(max_requests=10, window_seconds=60)
retrieve_limiter = RateLimiter(max_requests=30, window_seconds=60)
