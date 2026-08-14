import pytest

from app.models.enums import ScanStatus
from app.models.scan_job import ScanJob


def test_happy_path_transitions() -> None:
    job = ScanJob(id="s1", filename="a.apk")
    assert job.status == ScanStatus.QUEUED
    job.transition(ScanStatus.VALIDATING)
    job.transition(ScanStatus.STATIC_ANALYSIS)
    job.transition(ScanStatus.PREPARING_RUNTIME)
    job.transition(ScanStatus.DYNAMIC_ANALYSIS)
    job.transition(ScanStatus.AI_ANALYSIS)
    job.transition(ScanStatus.GENERATING_REPORT)
    job.transition(ScanStatus.COMPLETED)
    assert job.progress == 100
    assert job.completed_at is not None


def test_illegal_transition() -> None:
    job = ScanJob(id="s2", filename="a.apk")
    with pytest.raises(ValueError, match="Illegal scan transition"):
        job.transition(ScanStatus.COMPLETED)


def test_failed_from_validating() -> None:
    job = ScanJob(id="s3", filename="a.apk")
    job.transition(ScanStatus.VALIDATING)
    job.transition(ScanStatus.FAILED)
    assert job.status == ScanStatus.FAILED
