"""Generate a synthetic vulnerable APK for local Milestone 1 demos.

This does not use a real production application.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from tests.helpers import write_apk  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=ROOT / "workspace" / "samples" / "vulnerable-demo.apk",
    )
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_apk(args.output)
    print(args.output)


if __name__ == "__main__":
    main()
