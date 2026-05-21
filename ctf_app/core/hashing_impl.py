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


def compute_hashes(path: Path | str, chunk_size: int = 1024 * 1024) -> Dict[str, str]:
    
    try:
        h_md5 = hashlib.md5(usedforsecurity=False)
    except TypeError:  # Python builds without the OpenSSL usedforsecurity flag
        h_md5 = hashlib.md5()
    try:
        h_sha1 = hashlib.sha1(usedforsecurity=False)
    except TypeError:
        h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    p = Path(path)
    with p.open("rb") as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            h_md5.update(data)
            h_sha1.update(data)
            h_sha256.update(data)
    return {"md5": h_md5.hexdigest(), "sha1": h_sha1.hexdigest(), "sha256": h_sha256.hexdigest()}


def write_checksums(records: Mapping[str, Mapping[str, str]], output_file: Path | str) -> None:
    lines: List[str] = []
    for file_name in sorted(records):
        hashes = records[file_name]
        for algo in ("md5", "sha1", "sha256"):
            value = hashes.get(algo)
            if value:
                lines.append(f"{algo.upper()}  {value}  {file_name}")
    atomic_write_text(output_file, "\n".join(lines) + ("\n" if lines else ""))


def parse_expected_hashes(path: Optional[Path | str]) -> Dict[str, Dict[str, str]]:
    """
    Parse a relaxed expected-hash file.

    Supported line forms:
      SHA256  <hash>  <filename>
      <hash>  <filename>
      <filename>  <hash>
    """
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(p)
    result: Dict[str, Dict[str, str]] = {}
    hash_re = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\s+", line, maxsplit=2)
        algo = ""
        digest = ""
        filename = ""
        if len(parts) >= 3 and parts[0].lower() in {"md5", "sha1", "sha256"}:
            algo, digest, filename = parts[0].lower(), parts[1].lower(), parts[2]
        elif len(parts) >= 2 and hash_re.match(parts[0]):
            digest, filename = parts[0].lower(), parts[1]
            algo = {32: "md5", 40: "sha1", 64: "sha256"}[len(digest)]
        elif len(parts) >= 2 and hash_re.match(parts[-1]):
            filename, digest = parts[0], parts[-1].lower()
            algo = {32: "md5", 40: "sha1", 64: "sha256"}[len(digest)]
        else:
            continue
        result.setdefault(Path(filename).name, {})[algo] = digest
    return result


def compare_hashes(actual: Mapping[str, Mapping[str, str]], expected: Mapping[str, Mapping[str, str]]) -> List[Dict[str, str]]:
    comparisons: List[Dict[str, str]] = []
    if not expected:
        return comparisons
    for file_name, expected_hashes in expected.items():
        candidates = [file_name]
        candidates += [name for name in actual if Path(name).name == file_name]
        seen = set()
        for candidate in candidates:
            if candidate in seen or candidate not in actual:
                continue
            seen.add(candidate)
            for algo, exp_value in expected_hashes.items():
                act_value = actual[candidate].get(algo)
                if act_value:
                    comparisons.append({
                        "file": candidate,
                        "algo": algo,
                        "expected": exp_value,
                        "actual": act_value,
                        "status": "match" if act_value.lower() == exp_value.lower() else "mismatch",
                    })
    return comparisons

