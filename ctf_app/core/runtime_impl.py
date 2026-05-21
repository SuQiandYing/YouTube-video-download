# FOR CTF & SECURITY RESEARCH USE ONLY
"""
Shared utilities for ctf_ytdl_forensics.

This project is intended only for authorized CTF, security research, and
teaching environments. Do not use it to scrape, pirate, bypass DRM, or violate
service terms, robots.txt, or local law.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import socket
import string
import subprocess
import sys
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import requests
import yaml
from rich.console import Console
from rich.logging import RichHandler

BANNER = "FOR CTF & SECURITY RESEARCH USE ONLY"
console = Console()

DEFAULT_CONFIG: Dict[str, Any] = {
    "proxy": {
        # Disabled by default so first-time users do not hit WinError 10061
        # when no local proxy is running. Enable in GUI/CLI when needed.
        "enabled": False,
        "http": "http://127.0.0.1:7890",
        "https": "http://127.0.0.1:7890",
        "auto_disable_if_unreachable": True,
    },
    "download": {
        "output_dir": "./challenge_videos",
        "quality": "best",
        "concurrent": 5,
        "retry": 3,
        "rate_limit": None,
        "timeout": 30,
        "subtitles_langs": ["all"],
        "audio_format": "mp3",
        "playlist": False,
    },
    "analysis": {
        "enabled": True,
        "output_dir": "./analysis_results",
        "extract_keyframes": True,
        "generate_spectrogram": True,
        "run_binwalk": True,
        "run_exiftool": True,
        "run_zsteg": True,
        "max_keyframes": 150,
        "max_zsteg_frames": 80,
        "command_timeout": 180,
        "strings_min_length": 4,
        "tail_scan_bytes": 262144,
        "binwalk_extract": False,
    },
    "keywords": ["flag{", "CTF{", "FLAG", "ctf_"],
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

MEDIA_EXTENSIONS = {
    ".mp4", ".mkv", ".webm", ".mov", ".avi", ".flv", ".m4v",
    ".mp3", ".wav", ".flac", ".m4a", ".aac", ".opus", ".ogg",
}
SUBTITLE_EXTENSIONS = {".srt", ".vtt", ".ass", ".ssa", ".ttml", ".srv1", ".srv2", ".srv3"}
SIDECAR_EXTENSIONS = {".json", ".info.json", ".description", ".jpg", ".jpeg", ".png", ".webp"} | SUBTITLE_EXTENSIONS


class CommandResult:
    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def deep_update(base: Dict[str, Any], patch: Mapping[str, Any]) -> Dict[str, Any]:
    """Recursively merge patch into base and return base."""
    for key, value in patch.items():
        if isinstance(value, Mapping) and isinstance(base.get(key), dict):
            deep_update(base[key], value)
        else:
            base[key] = value
    return base


def load_config(path: Path | str = "config.yaml") -> Dict[str, Any]:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # cheap deep copy
    config_path = Path(path)
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"Config file must contain a YAML mapping: {config_path}")
        deep_update(cfg, loaded)
    return cfg


def ensure_dirs(*paths: Path | str) -> None:
    for p in paths:
        Path(p).mkdir(parents=True, exist_ok=True)


def setup_logging(level: str, log_dir: Optional[Path | str] = None) -> Tuple[logging.Logger, Optional[Path]]:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    rich_handler = RichHandler(console=console, rich_tracebacks=True, show_time=True, show_level=True, show_path=False)
    rich_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
    rich_handler.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(rich_handler)

    log_file = None
    if log_dir:
        try:
            ensure_dirs(log_dir)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = Path(log_dir) / f"run_{timestamp}.log"
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
            root.addHandler(file_handler)
        except Exception:
            pass

    logger = logging.getLogger("ctf_ytdl_forensics")
    if log_file:
        logger.debug("Logging initialized: %s", log_file)
    return logger, log_file


def require_python(min_version: Tuple[int, int] = (3, 10)) -> None:
    if sys.version_info < min_version:
        raise RuntimeError(f"Python {min_version[0]}.{min_version[1]}+ is required")


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def check_external_tools(names: Iterable[str], logger: Optional[logging.Logger] = None) -> Dict[str, Optional[str]]:
    found: Dict[str, Optional[str]] = {}
    for name in names:
        path = which(name)
        found[name] = path
        if logger:
            if path:
                logger.debug("Found external tool %-10s -> %s", name, path)
            else:
                logger.warning("External tool missing: %s", name)
    return found


def run_command(
    cmd: Sequence[str],
    timeout: Optional[int] = None,
    cwd: Optional[Path | str] = None,
    logger: Optional[logging.Logger] = None,
    env: Optional[Mapping[str, str]] = None,
) -> CommandResult:
    command = [str(c) for c in cmd]
    if logger:
        logger.debug("Running command: %s", " ".join(command))
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            env={**os.environ, **dict(env or {})},
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        if logger and proc.returncode != 0:
            logger.debug("Command returned %s: %s", proc.returncode, " ".join(command))
        return CommandResult(command, proc.returncode, proc.stdout, proc.stderr, False)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        if logger:
            logger.warning("Command timed out after %ss: %s", timeout, " ".join(command))
        return CommandResult(command, 124, stdout, stderr, True)
    except FileNotFoundError as exc:
        if logger:
            logger.warning("Command executable not found: %s", command[0])
        return CommandResult(command, 127, "", str(exc), False)

