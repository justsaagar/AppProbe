#!/usr/bin/env python3
"""Fail if tracked files contain realistic credential-like literals.

Detector regexes in application code are allowed. Contiguous provider keys,
JWT compact tokens, and high-entropy password assignments are not.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

STRIPE = re.compile(r"(?:sk|rk)_(?:live|test)_([A-Za-z0-9]{16,})")
JWT = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
AWS = re.compile(r"AKIA[0-9A-Z]{16}")
GITHUB = re.compile(r"ghp_[A-Za-z0-9]{20,}")
SLACK = re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")
GOOGLE = re.compile(r"AIza[0-9A-Za-z_\-]{20,}")
OPENAI = re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9]{20,}")
PASSWORD = re.compile(r"(?i)password\s*[=:]\s*[\"']([^\"']{10,})[\"']")
PEM = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----\s*([A-Za-z0-9+/=\n]{40,})")

SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".so", ".pyc"}


def tracked_files() -> list[Path]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    names = [item.decode() for item in raw.split(b"\0") if item]
    return [ROOT / name for name in names]


def is_known_aws_example(value: str) -> bool:
    return "EXAMPLE" in value


def is_explicitly_fake_password(value: str) -> bool:
    upper = value.upper()
    return "FAKE_" in upper or "APPPROBE" in upper or "TEST_ONLY" in upper


def scan_text(rel: str, text: str) -> list[str]:
    hits: list[str] = []
    if STRIPE.search(text):
        hits.append("stripe-shaped key literal")
    if JWT.search(text):
        hits.append("JWT compact token")
    for match in AWS.finditer(text):
        if not is_known_aws_example(match.group(0)):
            hits.append("AWS access key id")
            break
    if GITHUB.search(text):
        hits.append("GitHub token")
    if SLACK.search(text):
        hits.append("Slack token")
    if GOOGLE.search(text):
        hits.append("Google API key literal")
    if OPENAI.search(text):
        hits.append("OpenAI-shaped key")
    for match in PASSWORD.finditer(text):
        if not is_explicitly_fake_password(match.group(1)):
            hits.append("password assignment")
            break
    if PEM.search(text):
        hits.append("PEM private key block")
    return [f"{rel}: {item}" for item in hits]


def main() -> int:
    failures: list[str] = []
    for path in tracked_files():
        if path.suffix.lower() in SKIP_SUFFIXES or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(ROOT).as_posix()
        failures.extend(scan_text(rel, text))
    if failures:
        print("Credential-like literals found in tracked files:")
        for item in failures:
            print(f"  {item}")
        print("Use synthetic fixtures. Do not store provider-shaped secrets.")
        return 1
    print("No realistic credential literals found in tracked files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
