"""Scan job status transition rules."""

from __future__ import annotations

from app.models.enums import ScanStatus


class InvalidStateTransition(ValueError):
    pass


ALLOWED_TRANSITIONS: dict[ScanStatus, set[ScanStatus]] = {
    ScanStatus.QUEUED: {ScanStatus.VALIDATING, ScanStatus.FAILED},
    ScanStatus.VALIDATING: {ScanStatus.STATIC_ANALYSIS, ScanStatus.FAILED},
    ScanStatus.STATIC_ANALYSIS: {
        ScanStatus.PREPARING_RUNTIME,
        ScanStatus.GENERATING_REPORT,
        ScanStatus.FAILED,
    },
    ScanStatus.PREPARING_RUNTIME: {ScanStatus.DYNAMIC_ANALYSIS, ScanStatus.FAILED},
    ScanStatus.DYNAMIC_ANALYSIS: {ScanStatus.AI_ANALYSIS, ScanStatus.FAILED, ScanStatus.PARTIAL},
    ScanStatus.AI_ANALYSIS: {ScanStatus.GENERATING_REPORT, ScanStatus.FAILED},
    ScanStatus.GENERATING_REPORT: {
        ScanStatus.COMPLETED,
        ScanStatus.PARTIAL,
        ScanStatus.FAILED,
    },
    ScanStatus.COMPLETED: set(),
    ScanStatus.FAILED: set(),
    ScanStatus.PARTIAL: set(),
}


def can_transition(current: ScanStatus, target: ScanStatus) -> bool:
    if current == target:
        return True
    return target in ALLOWED_TRANSITIONS.get(current, set())


def transition(current: ScanStatus, target: ScanStatus) -> ScanStatus:
    if not can_transition(current, target):
        raise InvalidStateTransition(f"{current.value} -> {target.value} is not allowed")
    return target
