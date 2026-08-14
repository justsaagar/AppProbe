"""Named external executable. Adapters supply version arguments; this module does not."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolDefinition:
    """How to find an executable. Paths are not hardcoded to /usr/bin."""

    name: str
    executable: str
    version_args: tuple[str, ...] = ("--version",)
