"""Minimal async JSON HTTP helper.

Bounded timeouts, response size, and retries. Not a general HTTP framework.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

TRANSIENT_STATUS = {502, 503, 504}


class JsonHttpError(Exception):
    def __init__(
        self,
        kind: str,
        message: str,
        *,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.status_code = status_code


class JsonHttpClient:
    """POST/GET JSON with connection timeout, total timeout, and size limits."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 20.0,
        connect_timeout_seconds: float = 5.0,
        max_response_bytes: int = 1_048_576,
        retry_transient: int = 1,
        transport: httpx.BaseTransport | httpx.AsyncBaseTransport | None = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
        allow_empty: bool = False,
    ) -> None:
        self.timeout = httpx.Timeout(timeout_seconds, connect=connect_timeout_seconds)
        self.max_response_bytes = max_response_bytes
        self.retry_transient = max(0, min(retry_transient, 2))
        self.transport = transport
        self.headers = headers or {"Accept": "application/json"}
        self.follow_redirects = follow_redirects
        self.allow_empty = allow_empty

    async def post_json(self, url: str, payload: dict[str, Any]) -> Any:
        return await self._request("POST", url, payload=payload)

    async def get_json(self, url: str) -> Any:
        return await self._request("GET", url)

    async def post_form(self, url: str, data: dict[str, str]) -> Any:
        return await self._request("POST", url, form=data)

    async def post_multipart(
        self,
        url: str,
        *,
        files: dict[str, Any],
        data: dict[str, str] | None = None,
    ) -> Any:
        return await self._request("POST", url, form=data, files=files)

    async def _request(
        self,
        method: str,
        url: str,
        payload: dict[str, Any] | None = None,
        form: dict[str, str] | None = None,
        files: dict[str, Any] | None = None,
    ) -> Any:
        attempts = 1 + self.retry_transient
        last_error: JsonHttpError | None = None
        for attempt in range(attempts):
            try:
                return await self._once(method, url, payload=payload, form=form, files=files)
            except JsonHttpError as exc:
                last_error = exc
                retryable = exc.kind == "http_error" and exc.status_code in TRANSIENT_STATUS
                if not retryable or attempt >= attempts - 1:
                    raise
                logger.info("retrying %s after %s", method, exc.status_code)
        assert last_error is not None
        raise last_error

    async def _once(
        self,
        method: str,
        url: str,
        *,
        payload: dict[str, Any] | None,
        form: dict[str, str] | None = None,
        files: dict[str, Any] | None = None,
    ) -> Any:
        kwargs: dict[str, Any] = {
            "timeout": self.timeout,
            "headers": self.headers,
            "follow_redirects": self.follow_redirects,
        }
        if self.transport is not None:
            kwargs["transport"] = self.transport
        try:
            async with httpx.AsyncClient(**kwargs) as client:
                request_kwargs: dict[str, Any] = {}
                if payload is not None:
                    request_kwargs["json"] = payload
                elif files is not None:
                    request_kwargs["files"] = files
                    if form:
                        request_kwargs["data"] = form
                elif form is not None:
                    request_kwargs["data"] = form
                response = await client.request(method, url, **request_kwargs)
                body = await _read_limited(response, self.max_response_bytes)
        except httpx.TimeoutException as exc:
            raise JsonHttpError("timeout", f"HTTP timeout contacting configured endpoint: {exc}") from exc
        except httpx.HTTPError as exc:
            raise JsonHttpError("unavailable", f"HTTP connection failed: {exc}") from exc

        status = response.status_code
        if not self.follow_redirects and 300 <= status < 400:
            raise JsonHttpError(
                "http_error",
                "HTTP redirect from configured endpoint was not followed",
                status_code=status,
            )
        if status in {401, 403}:
            raise JsonHttpError(
                "auth_failed",
                f"HTTP {status} from configured endpoint",
                status_code=status,
            )
        if status == 429:
            raise JsonHttpError(
                "rate_limited",
                "HTTP 429 rate limited by configured endpoint",
                status_code=429,
            )
        if status >= 500:
            raise JsonHttpError(
                "http_error",
                f"HTTP {status} from configured endpoint",
                status_code=status,
            )
        if status >= 400:
            raise JsonHttpError(
                "http_error",
                f"HTTP {status} from configured endpoint",
                status_code=status,
            )
        if not body and self.allow_empty:
            return {}
        return _parse_json(body, url)


async def _read_limited(response: httpx.Response, max_bytes: int) -> bytes:
    declared = response.headers.get("Content-Length")
    if declared is not None:
        try:
            length = int(declared)
        except ValueError:
            length = -1
        if length > max_bytes:
            raise JsonHttpError("too_large", f"HTTP Content-Length {length} exceeds {max_bytes} bytes")
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > max_bytes:
            raise JsonHttpError("too_large", f"HTTP response exceeded {max_bytes} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _parse_json(body: bytes, url: str) -> Any:
    if not body:
        raise JsonHttpError("invalid_response", f"Empty JSON body from {url}")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JsonHttpError("invalid_response", f"Non-UTF8 JSON body from {url}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise JsonHttpError("invalid_response", f"Malformed JSON from {url}: {exc}") from exc
