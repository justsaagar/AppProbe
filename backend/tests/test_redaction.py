from app.utils.redaction import redact_secret, redact_text


def test_redact_live_key_matches_report_style() -> None:
    redacted = redact_secret("sk_live_abcdefghijklmnopqrst1234")
    assert redacted.startswith("sk_live_")
    assert redacted.endswith("1234")
    assert "*" in redacted
    assert "abcdefghijklmnop" not in redacted


def test_redact_text_hides_password_assignment() -> None:
    text = redact_text("password=super-secret-value")
    assert "super-secret-value" not in text
    assert "password=" in text
