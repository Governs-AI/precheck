import json
import sys
import time
from typing import Any, Dict

def audit_log(event_type: str, **fields: Any) -> None:
    """Log structured JSON audit events to stdout for shipping to Loki/Datadog"""
    record = {"t": int(time.time()), "event": event_type, **fields}
    sys.stdout.write(json.dumps(record, separators=(",", ":")) + "\n")
    sys.stdout.flush()
