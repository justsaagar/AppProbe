"""Generate a synthetic vulnerable APK for local demos.

This does not use a real production application and must not embed real
credentials. Provider-shaped detector inputs are assembled at runtime from
obviously fake components. Output is written under gitignored
`workspace/samples/`.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from tests.helpers import write_apk  # noqa: E402


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _synthetic_assets() -> dict[str, bytes]:
    stripe = "".join(("sk", "_", "live", "_", "APPPROBETESTONLYNOTAREALKEY"))
    fake_pwd = "FAKE_PASSWORD_FOR_SECURITY_TEST_ONLY"
    header = _b64url(b'{"alg":"none","typ":"JWT","kid":"APPPROBE-TEST-ONLY"}')
    payload = _b64url(b'{"sub":"appprobe-test-user","iss":"appprobe.example.test"}')
    signature = _b64url(b"APPPROBE-TEST-SIGNATURE-NOT-A-SECRET")
    token = ".".join((header, payload, signature))
    pem = "\n".join(
        (
            "-----BEGIN RSA PRIVATE KEY-----",
            "APPPROBE_TEST_ONLY_NOT_A_REAL_PRIVATE_KEY_BLOCK",
            "-----END RSA PRIVATE KEY-----",
        )
    )
    google = "".join(("AIza", "Sy", "AppProbeTestPublicClientKey00001"))
    firebase = json.dumps(
        {
            "project_info": {
                "project_id": "demo-app",
                "storage_bucket": "demo-app.appspot.com",
            },
            "client": [{"api_key": [{"current_key": google}]}],
        }
    )
    secrets_txt = (
        f"api={stripe}\n"
        f'token="{token}"\n'
        f"{pem}\n"
        f'pwd="{fake_pwd}"\n'
    )
    return {
        "assets/secrets.txt": secrets_txt.encode(),
        "google-services.json": firebase.encode(),
    }


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
    write_apk(args.output, extra_files=_synthetic_assets())
    print(args.output)


if __name__ == "__main__":
    main()
