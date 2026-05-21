# FOR CTF & SECURITY RESEARCH USE ONLY
from __future__ import annotations

import argparse
import logging
import threading
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from rich.progress import Progress, TaskID

from .downloader_helpers import DownloaderHelperMixin
from .downloader_orchestration import DownloaderOrchestrationMixin
from ..core.utils import ensure_dirs


class YtDlpLogger:
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    def debug(self, msg: str) -> None:
        self.logger.debug(msg) if msg.startswith("[debug] ") else self.logger.info(msg)
    def warning(self, msg: str) -> None:
        self.logger.warning(msg)
    def error(self, msg: str) -> None:
        self.logger.error(msg)


class CTFYouTubeDownloader(DownloaderOrchestrationMixin, DownloaderHelperMixin):
    def __init__(self, config: Mapping[str, Any], args: argparse.Namespace, logger: logging.Logger):
        self.config = config
        self.args = args
        self.logger = logger
        self.download_cfg = dict(config.get("download", {}))
        self.analysis_cfg = dict(config.get("analysis", {}))
        self.output_dir = Path(args.output_dir or self.download_cfg.get("output_dir", "./challenge_videos"))
        self.analysis_enabled = (not self.args.no_analysis) and bool(self.analysis_cfg.get("enabled", True))
        self.results_dir = Path(args.results_dir or self.analysis_cfg.get("output_dir", "./analysis_results"))
        self.sidecar_dir: Optional[Path] = (self.results_dir / "download_sidecars") if self.analysis_enabled else None
        self.checksums_file = (self.results_dir / "checksums.txt") if self.analysis_enabled else None
        ensure_dirs(self.output_dir)
        if self.analysis_enabled and self.sidecar_dir is not None:
            ensure_dirs(self.results_dir, self.sidecar_dir)
        self.lock = threading.Lock()
        self.progress: Optional[Progress] = None
        self.task_ids: Dict[str, TaskID] = {}
