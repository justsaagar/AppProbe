"""MobSF REST client.

Talks only to the configured MobSF origin. Does not scrape the UI, follow
advisory URLs, or enable dynamic analysis endpoints.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from app.mobsf.url import join_mobsf, validate_mobsf_url
from app.models.mobsf import (
    MobSFAvailability,
    MobSFHealth,
    MobSFScanProgress,
    MobSFUpload,
)
from app.utils.http import JsonHttpClient, JsonHttpError
from app.utils.redact import redact_text

logger = logging.getLogger(__name__)

Sleep = Callable[[float], Awaitable[None]]


class MobSFClient(ABC):
    """Provider abstraction used by the MobSF scanner."""

    @abstractmethod
    async def health(self) -> MobSFHealth:
        raise NotImplementedError

    @abstractmethod
    async def upload(self, artifact: Path) -> MobSFUpload:
        raise NotImplementedError

    @abstractmethod
    async def scan(self, *, scan_id: str, scan_type: str, file_name: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def status(self, scan_id: str) -> MobSFScanProgress:
        raise NotImplementedError

    @abstractmethod
    async def report(self, scan_id: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def cleanup(self, scan_id: str) -> None:
        raise NotImplementedError


class HttpMobSFClient(MobSFClient):
    """REST client for MobSF `/api/v1` static-analysis endpoints."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str = "",
        timeout_seconds: float = 30.0,
        connect_timeout_seconds: float = 5.0,
        max_response_bytes: int = 8 * 1024 * 1024,
        scan_timeout_seconds: float | None = None,
        transport: Any | None = None,
        client: JsonHttpClient | None = None,
        scan_client: JsonHttpClient | None = None,
    ) -> None:
        self.base_url = validate_mobsf_url(base_url)
        self._api_key = api_key or ""
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["Authorization"] = self._api_key
        shared = {
            "connect_timeout_seconds": connect_timeout_seconds,
            "max_response_bytes": max_response_bytes,
            "retry_transient": 0,
            "transport": transport,
            "headers": headers,
            "follow_redirects": False,
        }
        self.client = client or JsonHttpClient(timeout_seconds=timeout_seconds, **shared)
        self.scan_client = scan_client or JsonHttpClient(
            timeout_seconds=scan_timeout_seconds or timeout_seconds,
            **shared,
        )
        self._cleanup_client = JsonHttpClient(
            timeout_seconds=timeout_seconds,
            allow_empty=True,
            **shared,
        )

    async def health(self) -> MobSFHealth:
        try:
            payload = await self.client.get_json(self._url("/api/v1/scans"))
        except JsonHttpError as exc:
            return _health_from_error(exc)
        version = _version_from_payload(payload)
        return MobSFHealth(
            availability=MobSFAvailability.AVAILABLE,
            version=version,
            reason="MobSF REST API responded.",
        )

    async def upload(self, artifact: Path) -> MobSFUpload:
        with artifact.open("rb") as handle:
            payload = await self.client.post_multipart(
                self._url("/api/v1/upload"),
                files={"file": (artifact.name, handle, "application/octet-stream")},
            )
        if not isinstance(payload, dict):
            raise JsonHttpError("invalid_response", "MobSF upload response was not an object")
        if payload.get("error"):
            raise JsonHttpError("http_error", "MobSF upload was rejected")
        scan_id = str(payload.get("hash") or payload.get("scan_id") or "").strip()
        if not scan_id:
            raise JsonHttpError("invalid_response", "MobSF upload did not return a scan hash")
        logger.info("mobsf upload completed scan_id=%s", scan_id)
        return MobSFUpload(
            scan_id=scan_id,
            scan_type=str(payload.get("scan_type") or "apk"),
            file_name=str(payload.get("file_name") or artifact.name),
        )

    async def scan(self, *, scan_id: str, scan_type: str, file_name: str) -> dict[str, Any]:
        logger.info("mobsf scan start scan_id=%s", scan_id)
        payload = await self.scan_client.post_form(
            self._url("/api/v1/scan"),
            {
                "hash": scan_id,
                "scan_type": scan_type,
                "file_name": file_name,
                "re_scan": "0",
            },
        )
        if not isinstance(payload, dict):
            raise JsonHttpError("invalid_response", "MobSF scan response was not an object")
        error = payload.get("error")
        if isinstance(error, str) and error:
            raise JsonHttpError("http_error", "MobSF scan initiation failed")
        return payload

    async def status(self, scan_id: str) -> MobSFScanProgress:
        try:
            payload = await self.client.post_form(self._url("/api/v1/scan_logs"), {"hash": scan_id})
        except JsonHttpError as exc:
            if exc.status_code in {400, 404}:
                return MobSFScanProgress(status="pending")
            raise
        if not isinstance(payload, dict):
            return MobSFScanProgress(status="unknown")
        logs = payload.get("logs")
        text = ""
        if isinstance(logs, list) and logs:
            last = logs[-1]
            if isinstance(last, dict):
                text = str(last.get("status") or last.get("title") or "")
            else:
                text = str(last)
        lowered = text.lower()
        failed = any(token in lowered for token in ("fail", "error", "abort"))
        completed = any(token in lowered for token in ("completed", "finished", "success", "done"))
        return MobSFScanProgress(completed=completed and not failed, failed=failed, status=text or "pending")

    async def report(self, scan_id: str) -> dict[str, Any]:
        payload = await self.client.post_form(self._url("/api/v1/report_json"), {"hash": scan_id})
        if not isinstance(payload, dict):
            raise JsonHttpError("invalid_response", "MobSF report was not an object")
        return payload

    async def cleanup(self, scan_id: str) -> None:
        await self._cleanup_client.post_form(self._url("/api/v1/delete_scan"), {"hash": scan_id})
        logger.info("mobsf cleanup requested scan_id=%s", scan_id)

    def _url(self, path: str) -> str:
        return join_mobsf(self.base_url, path)


def _health_from_error(exc: JsonHttpError) -> MobSFHealth:
    if exc.kind == "auth_failed":
        return MobSFHealth(
            availability=MobSFAvailability.AUTH_FAILED,
            reason="MobSF rejected the configured API key.",
        )
    if exc.kind == "timeout":
        return MobSFHealth(
            availability=MobSFAvailability.TIMEOUT,
            reason="MobSF health check timed out.",
        )
    if exc.kind in {"unavailable", "invalid_url"}:
        return MobSFHealth(
            availability=MobSFAvailability.NOT_AVAILABLE,
            reason="MobSF REST endpoint was not reachable.",
        )
    return MobSFHealth(
        availability=MobSFAvailability.FAILED,
        reason=redact_text(exc.message) or "MobSF health check failed.",
    )


def _version_from_payload(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    value = payload.get("mobsf_version")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None
