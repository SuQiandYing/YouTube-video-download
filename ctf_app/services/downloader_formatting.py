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



class DownloaderFormattingMixin:
    def _make_ydl_logger(self):
        class _YtDlpLogger:
            def __init__(self, logger):
                self.logger = logger

            def debug(self, msg: str) -> None:
                self.logger.debug(msg) if msg.startswith("[debug] ") else self.logger.info(msg)

            def warning(self, msg: str) -> None:
                self.logger.warning(msg)

            def error(self, msg: str) -> None:
                self.logger.error(msg)

        return _YtDlpLogger(self.logger)

    def _build_ydl_opts(
        self,
        url: str,
        cookies_browser_override: Optional[str] = None,
        format_override: Optional[str] = None,
        download_subtitles: Optional[bool] = None,
    ) -> Dict[str, Any]:
        quality = self.args.quality or self.download_cfg.get("quality", "best")
        audio_only = bool(self.args.audio_only)
        audio_format = str(self.args.audio_format or self.download_cfg.get("audio_format", "mp3")).lower().strip()
        merge_output_format = str(getattr(self.args, "merge_output_format", None) or self.download_cfg.get("merge_output_format", "mp4")).lower().strip()
        remux_video = str(getattr(self.args, "remux_video", None) or self.download_cfg.get("remux_video", merge_output_format)).lower().strip()
        rate_limit = parse_rate_limit(self.args.limit_rate or self.download_cfg.get("rate_limit"))
        timeout = int(self.args.timeout or self.download_cfg.get("timeout", 30))
        retry = int(self.args.retry or self.download_cfg.get("retry", 3))
        proxy = self._select_proxy()
        sub_langs = self._sub_langs()
        if download_subtitles is None:
            download_subtitles = bool(sub_langs)
        task_id = self._create_progress_task(url)

        selected_format = format_override or self._format_selector(quality, audio_only)

        opts: Dict[str, Any] = {
            "format": selected_format,
            "outtmpl": {"default": "%(title).180B [%(id)s].%(ext)s"},
            "paths": {"home": str(self.output_dir), "temp": ".partial"},
            "continuedl": True,
            "nopart": False,
            "retries": retry,
            "fragment_retries": retry,
            "extractor_retries": retry,
            "file_access_retries": retry,
            "socket_timeout": timeout,
            "ratelimit": rate_limit,
            "concurrent_fragment_downloads": max(1, int(self.args.concurrent_fragments or self.download_cfg.get("concurrent_fragments", 4))),
            "noplaylist": not bool(self.args.playlist or self.download_cfg.get("playlist", False)),
            "writesubtitles": False,
            "writeautomaticsub": False,
            "writeinfojson": False,
            "clean_infojson": False,
            "writethumbnail": False,
            "writedescription": False,
            "getcomments": False,
            "allow_playlist_files": False,
            "ignoreerrors": False,
            "quiet": True,
            "no_warnings": False,
            "logger": self._make_ydl_logger(),
            "progress_hooks": [self._make_progress_hook(url, task_id)],
            "http_headers": {"User-Agent": random.choice(USER_AGENTS)},
            "windowsfilenames": True,
            "restrictfilenames": False,
            "overwrites": False,
        }
        if not audio_only and merge_output_format not in {"", "source", "keep", "original", "auto"}:
            opts["merge_output_format"] = merge_output_format
        if not audio_only and remux_video not in {"", "source", "keep", "original", "auto"}:
            opts["remuxvideo"] = remux_video
        self._ensure_ejs_options(opts)

        ffmpeg_exe = self._find_ffmpeg_binary()
        if ffmpeg_exe:
            # v11 fix: pass the exact executable path.  imageio-ffmpeg bundles
            # binaries named like ffmpeg-win64-v*.exe, not ffmpeg.exe; passing
            # only the parent directory makes yt-dlp look for ffmpeg.exe and it
            # reports "ffmpeg is not installed" even though the bundled binary
            # exists.  yt-dlp accepts either a directory or an exact binary path.
            opts["ffmpeg_location"] = str(Path(ffmpeg_exe))
            self.logger.info("Using ffmpeg binary: %s", ffmpeg_exe)
        elif not audio_only and not format_override and str(quality).lower().strip() == "best":
            # Last-resort fallback for systems with absolutely no ffmpeg, including
            # no imageio-ffmpeg. Only select already-muxed files so yt-dlp does not
            # need to merge separate audio/video streams.
            opts.pop("merge_output_format", None)
            opts["format"] = "best[vcodec!=none][acodec!=none]/worst[vcodec!=none][acodec!=none]"
            self.logger.warning("ffmpeg not found; falling back to muxed-only format to avoid merge failure")
        if proxy:
            opts["proxy"] = proxy
        if self.args.cookies:
            opts["cookiefile"] = str(Path(self.args.cookies))
        browser_spec = (cookies_browser_override or self.args.cookies_from_browser or "").strip()
        if browser_spec and browser_spec.lower() != "auto":
            opts["cookiesfrombrowser"] = self._parse_cookies_from_browser(browser_spec)
        if audio_only and audio_format not in {"", "source", "keep", "original", "best"}:
            opts.setdefault("postprocessors", []).append({
                "key": "FFmpegExtractAudio",
                "preferredcodec": audio_format,
                "preferredquality": "0",
            })
        if self.args.section:
            self._apply_download_section(opts, self.args.section)
        return opts

    def _parse_cookies_from_browser(self, spec: str) -> tuple:
        """Parse yt-dlp --cookies-from-browser syntax for Python API.

        CLI syntax: BROWSER[+KEYRING][:PROFILE][::CONTAINER]
        Python API expects: (browser_name, profile, keyring, container)
        """
        m = re.fullmatch(
            r"(?P<name>[^+:]+)(?:\s*\+\s*(?P<keyring>[^:]+))?(?:\s*:\s*(?!:)(?P<profile>.+?))?(?:\s*::\s*(?P<container>.+))?",
            spec.strip(),
        )
        if not m:
            raise ValueError(f"Invalid --cookies-from-browser value: {spec!r}")
        name = (m.group("name") or "").lower()
        keyring = m.group("keyring")
        profile = m.group("profile")
        container = m.group("container")
        return (name, profile, keyring.upper() if keyring else None, container)

    def _format_selector(self, quality: str, audio_only: bool) -> str:
        if audio_only:
            return "ba/bestaudio/b*"
        q = str(quality or "best").lower().strip()
        if q in {"best", "auto", "safe"}:
            # Robust default: prefer normal video+audio, but accept muxed or
            # reduced client format sets instead of failing immediately.
            return "bv*+ba/b/b*"
        if q.endswith("p") and q[:-1].isdigit():
            h = int(q[:-1])
            return f"bv*[height<={h}]+ba/b[height<={h}]/b/b*"
        return q

    def _apply_download_section(self, opts: Dict[str, Any], section: str) -> None:
        if download_range_func is None:
            self.logger.warning("yt-dlp download_range_func unavailable; --section skipped")
            return
        # yt-dlp 2026.x expects parsed numeric ranges here rather than the raw
        # "*start-end" CLI string syntax.
        opts["download_ranges"] = download_range_func(None, self._parse_download_section_ranges(section))
        opts["force_keyframes_at_cuts"] = True
        self.logger.info("Enabled partial download section: %s", section)

    @staticmethod
    def _parse_download_section_ranges(section: str) -> List[Tuple[float, float]]:
        ranges: List[Tuple[float, float]] = []
        for raw in [part.strip() for part in str(section).split(",") if part.strip()]:
            normalized = raw[1:] if raw.startswith("*") else raw
            if "-" not in normalized:
                raise ValueError(f"Invalid --section value {section!r}; expected start-end")
            start_text, end_text = normalized.split("-", 1)
            ranges.append((
                DownloaderFormattingMixin._parse_section_timestamp(start_text or "0"),
                DownloaderFormattingMixin._parse_section_timestamp(end_text or "inf"),
            ))
        if not ranges:
            raise ValueError("Empty --section value")
        return ranges

    @staticmethod
    def _parse_section_timestamp(value: str) -> float:
        text = str(value).strip().lower()
        if text in {"", "inf", "infinity"}:
            return float("inf")
        sign = -1 if text.startswith("-") else 1
        if sign < 0:
            text = text[1:]
        parts = text.split(":")
        if not 1 <= len(parts) <= 3:
            raise ValueError(f"Invalid timestamp {value!r}")
        total = 0.0
        for part in parts:
            total = total * 60 + float(part)
        return sign * total

    def _find_ffmpeg_binary(self) -> Optional[str]:
        exe = shutil.which("ffmpeg")
        if exe:
            return exe
        try:
            import imageio_ffmpeg  # type: ignore
            return str(imageio_ffmpeg.get_ffmpeg_exe())
        except Exception:
            return None

    def _detect_js_runtimes(self) -> Dict[str, Dict[str, str]]:
        candidates = [
            ("deno", ["deno", "deno.exe", str(Path.home() / ".deno" / "bin" / "deno.exe")]),
            ("node", ["node", "node.exe"]),
            ("bun", ["bun", "bun.exe"]),
            ("quickjs", ["qjs", "qjs.exe", "quickjs", "quickjs.exe"]),
        ]
        found: Dict[str, Dict[str, str]] = {}
        for name, names in candidates:
            for exe in names:
                path = exe if (Path(exe).exists() and Path(exe).is_file()) else shutil.which(exe)
                if path:
                    found[name] = {"path": str(path)}
                    break
        if found:
            self.logger.info("Detected JS runtimes for YouTube EJS: %s", ", ".join(found.keys()))
            return found
        self.logger.warning("No supported JS runtime detected. YouTube may expose only images. Run `python start.py --install-runtime` or install Deno.")
        return {"deno": {}}
