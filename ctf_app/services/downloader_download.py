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



class DownloaderDownloadMixin:
    def _download_once(self, url: str) -> None:
        try:
            import yt_dlp  # imported lazily so --help works before dependencies are installed
        except ImportError as exc:
            raise RuntimeError("yt-dlp is not installed. Run: python -m pip install -r requirements.txt") from exc

        browser_spec = (self.args.cookies_from_browser or "").strip()
        candidates = self._browser_cookie_candidates(browser_spec)
        errors: List[Tuple[Optional[str], str]] = []
        format_candidates = self._format_retry_candidates()

        for browser_override in candidates:
            for format_override in format_candidates:
                try:
                    if browser_override:
                        self.logger.info("Trying browser cookies: %s", browser_override)
                    if format_override:
                        self.logger.warning("Trying fallback format selector: %s", format_override)
                    prepared_opts = self._prepare_unique_media_outtmpl(
                        yt_dlp,
                        self._build_ydl_opts(url, cookies_browser_override=browser_override, format_override=format_override),
                        url,
                    )
                    self._run_yt_dlp_download(
                        yt_dlp,
                        prepared_opts,
                        url,
                    )
                    return
                except Exception as exc:
                    err = str(exc)
                    errors.append((browser_override, err))
                    low = err.lower()
                    if self._should_retry_without_subtitles(err):
                        self.logger.warning(
                            "Subtitle download failed; retrying %s without subtitles so media can still be captured",
                            url,
                        )
                        try:
                            prepared_opts = self._prepare_unique_media_outtmpl(
                                yt_dlp,
                                self._build_ydl_opts(
                                    url,
                                    cookies_browser_override=browser_override,
                                    format_override=format_override,
                                    download_subtitles=False,
                                ),
                                url,
                            )
                            self._run_yt_dlp_download(
                                yt_dlp,
                                prepared_opts,
                                url,
                            )
                            return
                        except Exception as fallback_exc:
                            err = str(fallback_exc)
                            errors.append((browser_override, err))
                            low = err.lower()
                            exc = fallback_exc
                    if "ffmpeg is not installed" in low and format_override != format_candidates[-1]:
                        self.logger.warning("ffmpeg merge failed; trying a muxed-only fallback selector")
                        continue
                    if "requested format is not available" in low and format_override != format_candidates[-1]:
                        self.logger.warning("Requested format unavailable; trying a safer fallback selector")
                        continue
                    if browser_spec.lower() == "auto" and browser_override:
                        self.logger.warning("Browser cookies failed for %s: %s", browser_override, self._strip_ansi(err))
                        break
                    if "failed to decrypt with dpapi" in low or "could not find" in low or "permission denied" in low:
                        raise NonRetryableDownloadError(err) from exc
                    raise

        if errors:
            summary = self._summarize_browser_cookie_errors(errors)
            if self._is_non_retryable_error(summary):
                raise NonRetryableDownloadError(summary)
            raise RuntimeError(summary)
        raise RuntimeError("No cookie candidates were available. Use --cookies cookies.txt or --cookies-from-browser chrome:Default/edge:Profile 1")

    @staticmethod
    def _run_yt_dlp_download(yt_dlp_module: Any, opts: Dict[str, Any], url: str | None = None) -> None:
        targets = [url] if url else []
        ffmpeg_ctx = None
        ffmpeg_token = None
        ffmpeg_location = opts.get("ffmpeg_location")
        if ffmpeg_location:
            try:
                from yt_dlp.postprocessor.ffmpeg import FFmpegPostProcessor

                ffmpeg_ctx = FFmpegPostProcessor
                ffmpeg_token = ffmpeg_ctx._ffmpeg_location.set(str(ffmpeg_location))
            except Exception:
                ffmpeg_ctx = None
                ffmpeg_token = None
        try:
            with yt_dlp_module.YoutubeDL(opts) as ydl:
                rc = ydl.download(targets)
            if rc != 0:
                raise RuntimeError(f"yt-dlp returned non-zero code {rc}")
        finally:
            if ffmpeg_ctx is not None and ffmpeg_token is not None:
                ffmpeg_ctx._ffmpeg_location.reset(ffmpeg_token)

    def _prepare_unique_media_outtmpl(self, yt_dlp_module: Any, opts: Dict[str, Any], url: str) -> Dict[str, Any]:
        probe_opts = dict(opts)
        probe_opts["progress_hooks"] = []
        try:
            with yt_dlp_module.YoutubeDL(probe_opts) as ydl:
                info = ydl.extract_info(url, download=False)
                if not isinstance(info, dict) or info.get("_type") == "playlist":
                    return opts
                planned = Path(ydl.prepare_filename(info))
        except Exception as exc:
            self.logger.debug("Could not precompute output filename for %s: %s", url, exc)
            return opts

        unique = self._unique_media_path(planned)
        if unique == planned:
            return opts

        updated = dict(opts)
        updated["outtmpl"] = {"default": str(unique.with_suffix("")) + ".%(ext)s"}
        self.logger.info("Output file exists; using unique filename: %s", unique.name)
        return updated

    @staticmethod
    def _unique_media_path(target: Path) -> Path:
        if not target.exists():
            return target
        stem = target.stem
        suffix = target.suffix
        parent = target.parent
        counter = 1
        candidate = target
        while candidate.exists():
            candidate = parent / f"{stem} ({counter}){suffix}"
            counter += 1
        return candidate

    def _should_retry_without_subtitles(self, error: str) -> bool:
        return self._subtitles_requested() and "unable to download video subtitles" in str(error).lower()

    def _format_retry_candidates(self) -> List[Optional[str]]:
        """Return increasingly permissive format selectors.

        YouTube sometimes exposes only a reduced format set when cookies or new
        player clients are involved. In that case a strict height selector, or
        even a normal bestvideo+bestaudio selector, can fail with
        "Requested format is not available". The fallbacks prioritize getting
        an analyzable media file for CTF work over preserving ideal quality.
        """
        quality = str(self.args.quality or self.download_cfg.get("quality", "best")).lower().strip()
        audio_only = bool(self.args.audio_only)
        muxed_only = "best[vcodec!=none][acodec!=none]/worst[vcodec!=none][acodec!=none]"
        if audio_only:
            base = [None, "ba/bestaudio/b*"]
        elif quality.endswith("p") and quality[:-1].isdigit():
            h = int(quality[:-1])
            base = [
                None,
                f"bv*[height<={h}]+ba/b[height<={h}]/b/b*",
                "bv*+ba/b/b*",
                muxed_only,
                "best/b*",
            ]
        else:
            base = [None, "bv*+ba/b/b*", muxed_only, "best/b*", "b*"]
        out: List[Optional[str]] = []
        for item in base:
            if item not in out:
                out.append(item)
        return out

