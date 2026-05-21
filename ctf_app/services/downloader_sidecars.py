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


class DownloaderSidecarMixin:
    def _relocate_existing_sidecars(self) -> None:
        if self.sidecar_dir is None:
            return
        moved = self._relocate_sidecars(str(p.resolve()) for p in list_files(self.output_dir))
        if moved:
            self.logger.info("Moved %s sidecar files into %s to keep the media folder clean", len(moved), self.sidecar_dir)

    def _relocate_sidecars(self, files: Iterable[str]) -> List[str]:
        if self.sidecar_dir is None:
            return []
        moved: List[str] = []
        for raw in sorted(set(str(f) for f in files)):
            path = Path(raw)
            if not self._should_relocate_sidecar(path):
                continue
            ensure_dirs(self.sidecar_dir)
            target = self._artifact_target_for(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.resolve() == path.resolve():
                moved.append(str(target))
                continue
            if target.exists():
                try:
                    same_file = target.stat().st_size == path.stat().st_size
                except OSError:
                    same_file = False
                if same_file:
                    path.unlink(missing_ok=True)
                    moved.append(str(target))
                    continue
                target = self._unique_sidecar_path(target)
            shutil.move(str(path), str(target))
            moved.append(str(target))
        return moved

    def _should_relocate_sidecar(self, path: Path) -> bool:
        if not path.exists() or not path.is_file():
            return False
        if path.name == ".gitkeep":
            return False
        if path.name == "checksums.txt":
            return True
        return path.suffix.lower() in SIDECAR_EXTENSIONS

    def _artifact_target_for(self, path: Path) -> Path:
        if path.name == "checksums.txt" and self.checksums_file is not None:
            return self.checksums_file
        if self.sidecar_dir is None:
            return path
        return self.sidecar_dir / path.name

    @staticmethod
    def _unique_sidecar_path(target: Path) -> Path:
        stem = target.stem
        suffix = target.suffix
        parent = target.parent
        counter = 1
        candidate = target
        while candidate.exists():
            candidate = parent / f"{stem}_{counter}{suffix}"
            counter += 1
        return candidate

