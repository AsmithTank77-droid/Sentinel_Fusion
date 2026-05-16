"""
intelligence/_http.py — Lightweight stdlib HTTP helper for intelligence API calls.

Uses only urllib.request and json — no external dependencies.
All calls are synchronous with a configurable timeout.
Failures raise _IntelHttpError rather than propagating raw urllib exceptions
so callers can catch one exception type and fall back gracefully.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class IntelHttpError(Exception):
    """Raised when an intelligence API call fails for any reason."""


def get_json(url: str, headers: dict[str, str] | None = None, timeout: int = 5) -> Any:
    """
    Perform a GET request and return the parsed JSON body.

    Args:
        url:     Full request URL.
        headers: Optional extra request headers (e.g. API key).
        timeout: Request timeout in seconds.

    Returns:
        Parsed JSON (dict, list, or scalar).

    Raises:
        IntelHttpError: on any network error, non-2xx response, or JSON parse failure.
    """
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raise IntelHttpError(f"HTTP {exc.code} from {url}") from exc
    except urllib.error.URLError as exc:
        raise IntelHttpError(f"Network error reaching {url}: {exc.reason}") from exc
    except OSError as exc:
        raise IntelHttpError(f"OS error during request to {url}: {exc}") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IntelHttpError(f"Invalid JSON from {url}: {exc}") from exc
