import time
from datetime import datetime, timedelta, timezone
from typing import Optional


def next_utc_midnight(now: Optional[datetime] = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    return (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)


class FreeTierState:
    """Whether the server's shared model key can take requests right now.

    When the provider says the per-minute or per-day allowance is used up,
    scans skip the model until it resets instead of sending requests that
    are bound to fail. Kept in memory: the app runs as one process, and after
    a restart the first request simply finds out again.
    """

    def __init__(self):
        self.busy_until = 0.0
        self.exhausted_until = 0.0

    def mark_busy(self, seconds: Optional[float]) -> None:
        wait = min(max(seconds or 60, 5), 600)
        self.busy_until = max(self.busy_until, time.time() + wait)

    def mark_exhausted(self, seconds: Optional[float]) -> None:
        if seconds:
            until = time.time() + seconds
        else:
            until = next_utc_midnight().timestamp()
        self.exhausted_until = max(self.exhausted_until, until)

    def status(self) -> dict:
        now = time.time()
        if self.exhausted_until > now:
            return {
                "state": "exhausted",
                "retry_after": round(self.exhausted_until - now),
                "resets_at": datetime.fromtimestamp(
                    self.exhausted_until, timezone.utc
                ).isoformat(),
            }
        if self.busy_until > now:
            return {
                "state": "busy",
                "retry_after": round(self.busy_until - now),
                "resets_at": None,
            }
        return {"state": "ok", "retry_after": 0, "resets_at": None}

    def reset(self) -> None:
        self.busy_until = self.exhausted_until = 0.0


free_tier = FreeTierState()
