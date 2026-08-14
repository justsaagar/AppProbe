"""Locate executables without running them."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def resolve_executable(executable: str | None, *candidates: str) -> str | None:
    """Return a filesystem path for the first existing executable.

    Uses ``shutil.which`` for names on ``PATH`` and a direct file check for
    explicit paths. Never executes the binary and never interpolates a shell.
    """
    names: list[str] = []
    if executable:
        names.append(executable)
    names.extend(candidate for candidate in candidates if candidate)
    for name in names:
        path = Path(name)
        if path.is_file():
            return str(path)
        found = shutil.which(name)
        if found:
            return found
        if os.path.sep in name or (os.path.altsep and os.path.altsep in name):
            # Explicit path that is not a file: do not search PATH by basename.
            continue
    return None
