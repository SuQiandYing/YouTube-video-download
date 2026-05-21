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


def search_keywords_text(text: str, keywords: Iterable[str], context: int = 80) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for keyword in keywords:
        if not keyword:
            continue
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        for match in pattern.finditer(text):
            start = max(0, match.start() - context)
            end = min(len(text), match.end() + context)
            hits.append({
                "keyword": keyword,
                "offset": match.start(),
                "context": text[start:end].replace("\x00", " "),
            })
    return hits


def search_keywords_file(path: Path | str, keywords: Iterable[str], max_bytes: Optional[int] = None) -> List[Dict[str, Any]]:
    p = Path(path)
    data = p.read_bytes()
    if max_bytes is not None:
        data = data[:max_bytes]
    text = data.decode("utf-8", errors="replace")
    return search_keywords_text(text, keywords)


def extract_printable_strings(path: Path | str, min_length: int = 4) -> List[str]:
    p = Path(path)
    printable = set(bytes(string.printable, "ascii"))
    strings_out: List[str] = []
    buf = bytearray()
    with p.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            for b in chunk:
                if b in printable and b not in b"\x0b\x0c":
                    buf.append(b)
                else:
                    if len(buf) >= min_length:
                        strings_out.append(buf.decode("latin-1", errors="replace"))
                    buf.clear()
    if len(buf) >= min_length:
        strings_out.append(buf.decode("latin-1", errors="replace"))
    return strings_out


def hex_preview(data: bytes, limit: int = 256) -> str:
    chunk = data[:limit]
    return " ".join(f"{b:02x}" for b in chunk)


def detect_mp4_appended_data(path: Path | str) -> Dict[str, Any]:
    """Heuristic top-level MP4 atom scan to detect trailing bytes after the last box."""
    p = Path(path)
    size = p.stat().st_size
    result: Dict[str, Any] = {"container": "mp4-family", "file_size": size, "last_box_end": None, "appended_bytes": 0}
    try:
        with p.open("rb") as f:
            offset = 0
            last_end = 0
            boxes: List[Dict[str, Any]] = []
            while offset + 8 <= size:
                f.seek(offset)
                header = f.read(16)
                if len(header) < 8:
                    break
                box_size = int.from_bytes(header[0:4], "big")
                box_type = header[4:8].decode("latin-1", errors="replace")
                header_size = 8
                if box_size == 1:
                    if len(header) < 16:
                        break
                    box_size = int.from_bytes(header[8:16], "big")
                    header_size = 16
                elif box_size == 0:
                    box_size = size - offset
                if box_size < header_size or offset + box_size > size:
                    break
                boxes.append({"offset": offset, "type": box_type, "size": box_size})
                last_end = offset + box_size
                offset = last_end
                if len(boxes) > 10000:
                    break
            result["last_box_end"] = last_end
            result["boxes_tail"] = boxes[-20:]
            if last_end and last_end < size:
                result["appended_bytes"] = size - last_end
    except Exception as exc:  # pragma: no cover - defensive
        result["error"] = str(exc)
    return result


