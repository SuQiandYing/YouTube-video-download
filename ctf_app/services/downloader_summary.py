from __future__ import annotations

import os
import random
import re
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from rich.progress import TaskID
from rich.table import Table

from .models import DownloadTaskResult, NonRetryableDownloadError
from ..core.utils import (
    SIDECAR_EXTENSIONS,
    USER_AGENTS,
    compute_hashes,
    console,
    ensure_dirs,
    list_files,
    parse_rate_limit,
    should_auto_disable_proxy,
)

try:
    from yt_dlp.utils import download_range_func
except Exception:  # pragma: no cover
    download_range_func = None  # type: ignore[assignment]


class DownloaderSummaryMixin:
    def _print_summary(self, summary: Mapping[str, Any]) -> None:
        table = Table(title="ctf_ytdl_forensics summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("URLs", str(len(summary.get("urls", []))))
        table.add_row("Downloaded files", str(len(summary.get("downloaded_files", []))))
        table.add_row("Media files", str(len(summary.get("media_files", []))))
        table.add_row("Artifact files", str(len(summary.get("artifact_files", []))))
        table.add_row("Failed tasks", str(len(summary.get("failed", []))))
        table.add_row("Checksums", str(summary.get("checksums_file")))
        table.add_row("Sidecar dir", str(summary.get("sidecar_dir")))
        table.add_row("JSON summary", str(self.results_dir / "task_results.json"))
        if summary.get("analysis_report"):
            table.add_row("HTML report", str(summary.get("analysis_report")))
        console.print(table)
        failed = summary.get("failed", [])
        if failed:
            console.print("[bold red]Failed tasks:[/bold red]")
            for item in failed:
                console.print(f"- {item.get('url')}: {item.get('error')}")
