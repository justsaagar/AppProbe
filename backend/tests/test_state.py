import pytest

from app.models.enums import ScanStatus
from app.models.state import InvalidStateTransition, can_transition, transition


def test_happy_path_transitions() -> None:
    current = ScanStatus.QUEUED
    for nxt in (
        ScanStatus.VALIDATING,
        ScanStatus.STATIC_ANALYSIS,
        ScanStatus.PREPARING_RUNTIME,
        ScanStatus.DYNAMIC_ANALYSIS,
        ScanStatus.AI_ANALYSIS,
        ScanStatus.GENERATING_REPORT,
        ScanStatus.COMPLETED,
    ):
        assert can_transition(current, nxt)
        current = transition(current, nxt)
    assert current is ScanStatus.COMPLETED


def test_failed_from_validating() -> None:
    assert transition(ScanStatus.VALIDATING, ScanStatus.FAILED) is ScanStatus.FAILED


def test_illegal_transition() -> None:
    with pytest.raises(InvalidStateTransition):
        transition(ScanStatus.COMPLETED, ScanStatus.QUEUED)
    with pytest.raises(InvalidStateTransition):
        transition(ScanStatus.QUEUED, ScanStatus.COMPLETED)
