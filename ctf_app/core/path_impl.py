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


def atomic_write_text(path: Path | str, text: str) -> None:
    p = Path(path)
    ensure_dirs(p.parent)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(p)


def atomic_write_json(path: Path | str, data: Any, indent: int = 2) -> None:
    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=indent, default=str))




def proxy_endpoint_reachable(proxy_url: str, timeout: float = 1.5) -> bool:
    """Return whether a local/remote proxy endpoint accepts TCP connections.

    This is only a convenience preflight. It does not prove the proxy can reach
    YouTube; it prevents common localhost connection-refused failures.
    """
    if not proxy_url:
        return False
    parsed = urlparse(proxy_url)
    host = parsed.hostname
    port = parsed.port
    if not host or not port:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def should_auto_disable_proxy(proxy_url: str) -> bool:
    """Only auto-disable localhost-style proxies when their port is closed."""
    parsed = urlparse(proxy_url)
    host = (parsed.hostname or "").lower()
    if host in {"127.0.0.1", "localhost", "::1"}:
        return not proxy_endpoint_reachable(proxy_url)
    return False


def fetch_robots_txt_status(url: str, proxy: Optional[str] = None, timeout: int = 10) -> Dict[str, Any]:
    """Best-effort robots.txt fetch using requests for compliance visibility.

    This function does not make a legal/ToS decision. It records whether a
    robots.txt file was reachable so the operator can review it in authorized
    CTF/security-research workflows.
    """
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return {"ok": False, "url": url, "error": "invalid URL"}
    robots_url = urljoin(f"{parsed.scheme}://{parsed.netloc}", "/robots.txt")
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        response = requests.get(
            robots_url,
            timeout=timeout,
            proxies=proxies,
            headers={"User-Agent": USER_AGENTS[0]},
        )
        text = response.text or ""
        return {
            "ok": response.ok,
            "robots_url": robots_url,
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type"),
            "preview": text[:1000],
        }
    except requests.RequestException as exc:
        return {"ok": False, "robots_url": robots_url, "error": str(exc)}

def parse_rate_limit(rate: Optional[str]) -> Optional[int]:
    if rate is None:
        return None
    if isinstance(rate, (int, float)):
        return int(rate)
    value = str(rate).strip()
    if not value:
        return None
    m = re.match(r"^(\d+(?:\.\d+)?)([kKmMgG]?)$", value)
    if not m:
        raise ValueError(f"Invalid rate limit: {rate}; examples: 500K, 2M")
    number = float(m.group(1))
    suffix = m.group(2).lower()
    multiplier = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[suffix]
    return int(number * multiplier)


def read_targets_file(path: Path | str) -> List[str]:
    p = Path(path)
    urls = []
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(line)
    return urls


def is_media_file(path: Path | str) -> bool:
    p = Path(path)
    if p.name.endswith(".part") or p.suffix == ".part":
        return False
    return p.suffix.lower() in MEDIA_EXTENSIONS


def is_subtitle_file(path: Path | str) -> bool:
    return Path(path).suffix.lower() in SUBTITLE_EXTENSIONS


def list_files(root: Path | str) -> List[Path]:
    r = Path(root)
    if not r.exists():
        return []
    return [p for p in r.rglob("*") if p.is_file()]


def newest_files_since(root: Path | str, timestamp: float) -> List[Path]:
    return [p for p in list_files(root) if p.stat().st_mtime >= timestamp]


def safe_stem(path: Path | str, max_len: int = 80) -> str:
    stem = Path(path).stem
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", stem).strip("._")
    return (stem or "artifact")[:max_len]


def tail_bytes(path: Path | str, count: int) -> bytes:
    p = Path(path)
    size = p.stat().st_size
    with p.open("rb") as f:
        f.seek(max(0, size - count))
        return f.read()
