"""Generic external-tool execution (discovery, process run, structured results).

This package is the reusable subprocess layer for later static-analysis
adapters. It does not implement JADX, apktool, MobSF, or bundletool.
"""

from app.models.enums import ToolExecutionStatus
from app.tools.definition import ToolDefinition
from app.tools.discovery import resolve_executable
from app.tools.executor import ExternalToolExecutor
from app.tools.result import ToolExecutionResult

__all__ = [
    "ExternalToolExecutor",
    "ToolDefinition",
    "ToolExecutionResult",
    "ToolExecutionStatus",
    "resolve_executable",
]
