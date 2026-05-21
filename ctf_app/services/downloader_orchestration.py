from __future__ import annotations

import json
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from .analyzer import ForensicAnalyzer
from .models import DownloadTaskResult, NonRetryableDownloadError
from ..core.utils import BANNER, atomic_write_json, compare_hashes, ensure_dirs, fetch_robots_txt_status, is_media_file, list_files, newest_files_since, parse_expected_hashes, require_python, write_checksums


class DownloaderOrchestrationMixin:
    def _cleanup_partial_dir(self) -> None:
        partial_dir = self.output_dir / ".partial"
        try:
            if partial_dir.exists() and partial_dir.is_dir() and not any(partial_dir.iterdir()):
                partial_dir.rmdir()
        except Exception:
            pass

    def _show_banner(self) -> None:
        from rich.panel import Panel
        from ..core.utils import console
        text = f"[bold yellow]{BANNER}[/bold yellow]\nAuthorized CTF / security research / teaching only. Do not bypass DRM, scrape without permission, or violate service terms / robots.txt / local law."
        console.print(Panel.fit(text, title="ctf_ytdl_forensics", border_style="yellow"))

    def _log_robots_status(self, url: str) -> None:
        status = fetch_robots_txt_status(url, proxy=self._select_proxy(), timeout=int(self.args.timeout or self.download_cfg.get("timeout", 30)))
        robots_log = self.results_dir / "robots_checks.jsonl"
        ensure_dirs(robots_log.parent)
        with robots_log.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"url": url, **status}, ensure_ascii=False) + "\n")

    def _preflight(self) -> None:
        from ..core.utils import check_external_tools
        require_python((3, 10))
        check_external_tools(["ffmpeg", "ffprobe", "exiftool", "binwalk", "strings", "zsteg"], self.logger)

    def _download_with_retries(self, url: str) -> DownloadTaskResult:
        max_attempts = max(1, int(self.args.retry or self.download_cfg.get("retry", 3)))
        started = time.time()
        before_files = {str(p.resolve()) for p in list_files(self.output_dir)}
        last_error: Optional[str] = None
        for attempt in range(1, max_attempts + 1):
            try:
                self._download_once(url)
                raw_outputs = self._collect_recent_output_files(before_files, started)
                artifact_files = self._relocate_sidecars(raw_outputs)
                media = self._resolve_media_outputs(url, raw_outputs, artifact_files)
                self._cleanup_partial_dir()
                print(f"[GUI_STATUS] {json.dumps({'url': url, 'status': 'done', 'media_files': media}, ensure_ascii=False)}", flush=True, file=sys.stdout)
                return DownloadTaskResult(url, True, attempt, media, media, artifact_files, None, round(time.time() - started, 3))
            except Exception as exc:
                last_error = self._friendly_error(str(exc))
                if isinstance(exc, NonRetryableDownloadError) or self._is_non_retryable_error(last_error):
                    print(f"[GUI_STATUS] {json.dumps({'url': url, 'status': 'error', 'error': last_error}, ensure_ascii=False)}", flush=True, file=sys.stdout)
                    return DownloadTaskResult(url, False, attempt, [], [], [], last_error, round(time.time() - started, 3))
                if attempt < max_attempts:
                    time.sleep(min(60, 2 ** (attempt - 1) + random.random()))
        print(f"[GUI_STATUS] {json.dumps({'url': url, 'status': 'error', 'error': last_error}, ensure_ascii=False)}", flush=True, file=sys.stdout)
        return DownloadTaskResult(url, False, max_attempts, [], [], [], last_error, round(time.time() - started, 3))

    def _collect_recent_output_files(self, before_files: Set[str], started: float) -> List[str]:
        after = {str(p.resolve()) for p in list_files(self.output_dir)}
        new_or_changed = sorted(after - before_files)
        recent = [str(p.resolve()) for p in newest_files_since(self.output_dir, started - 2)]
        return sorted(set(new_or_changed) | set(recent))

    @staticmethod
    def _should_disable_rich_progress() -> bool:
        encoding = (getattr(sys.stdout, "encoding", None) or "").lower()
        import os
        return os.name == "nt" and "utf" not in encoding

    def _resolve_media_outputs(self, url: str, raw_outputs: Sequence[str], artifact_files: Sequence[str]) -> List[str]:
        media = sorted(str(Path(p).resolve()) for p in raw_outputs if is_media_file(p))
        if media:
            return media
        id_candidates = self._extract_output_ids([*raw_outputs, *artifact_files])
        url_id = self._extract_url_identifier(url)
        if url_id:
            id_candidates.add(url_id)
        existing_media = [str(p.resolve()) for p in list_files(self.output_dir) if is_media_file(p)]
        return sorted({path for path in existing_media if any(f"[{candidate}]" in Path(path).name for candidate in id_candidates)})

    @staticmethod
    def _extract_output_ids(paths: Sequence[str]):
        import re
        ids = set()
        for path in paths:
            match = re.search(r"\[([A-Za-z0-9_-]{6,})\]", Path(path).name)
            if match:
                ids.add(match.group(1))
        return ids

    @staticmethod
    def _extract_url_identifier(url: str):
        import re
        for pattern in [r"[?&]v=([A-Za-z0-9_-]{6,})", r"youtu\.be/([A-Za-z0-9_-]{6,})", r"/shorts/([A-Za-z0-9_-]{6,})"]:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        return None

    def run(self, urls: Sequence[str]) -> Dict[str, Any]:
        if not urls:
            raise ValueError("No URLs provided. Use positional URL or --targets targets.txt")
        self._show_banner()
        self._preflight()
        if self.analysis_enabled:
            self._relocate_existing_sidecars()
        if self.args.check_robots or self.config.get("compliance", {}).get("check_robots_txt", False):
            for u in urls:
                self._log_robots_status(u)
        expected_hashes = parse_expected_hashes(self.args.expected_hashes)
        start_time = time.time()
        concurrency = max(1, int(self.args.concurrent or self.download_cfg.get("concurrent", 5)))
        all_results: List[DownloadTaskResult] = []
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, DownloadColumn, TransferSpeedColumn, TimeRemainingColumn
        progress = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), DownloadColumn(), TransferSpeedColumn(), TimeRemainingColumn(), transient=False, disable=self._should_disable_rich_progress())
        self.progress = progress
        with progress:
            if concurrency == 1 or len(urls) == 1:
                for url in urls:
                    all_results.append(self._download_with_retries(url))
            else:
                from concurrent.futures import ThreadPoolExecutor, as_completed
                with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="ytdlp") as pool:
                    future_map = {pool.submit(self._download_with_retries, url): url for url in urls}
                    for future in as_completed(future_map):
                        all_results.append(future.result())
        all_downloaded = sorted({p for r in all_results for p in r.downloaded_files})
        media_files = sorted({p for r in all_results for p in r.media_files})
        artifact_files = sorted({p for r in all_results for p in r.artifact_files})
        checksums: Dict[str, Dict[str, str]] = {}
        comparisons: Dict[str, Any] = {}
        if self.checksums_file is not None:
            checksums = self._hash_downloaded_files(all_downloaded)
            write_checksums(checksums, self.checksums_file)
            comparisons = compare_hashes(checksums, expected_hashes)
        if self.analysis_enabled and media_files:
            analyzer_cfg = json.loads(json.dumps(self.config))
            analyzer_cfg.setdefault("analysis", {})["output_dir"] = str(self.results_dir)
            analyzer = ForensicAnalyzer(analyzer_cfg, logger=self.logger)
            subtitle_roots = [self.output_dir] + ([self.sidecar_dir] if self.sidecar_dir is not None else [])
            analyzer.analyze_many([Path(p) for p in media_files], subtitle_roots=subtitle_roots)
        summary = {"tool": "ctf_ytdl_forensics", "banner": BANNER, "started_at": start_time, "elapsed_seconds": round(time.time() - start_time, 3), "urls": list(urls), "download_results": [r.to_dict() for r in all_results], "failed": [r.to_dict() for r in all_results if not r.ok], "downloaded_files": all_downloaded, "media_files": media_files, "artifact_files": artifact_files, "sidecar_dir": str(self.sidecar_dir) if self.sidecar_dir is not None else None, "checksums_file": str(self.checksums_file) if self.checksums_file is not None else None, "checksums": checksums, "expected_hash_comparisons": comparisons, "analysis_enabled": self.analysis_enabled, "analysis_summary": str(self.results_dir / 'analysis_summary.json') if self.analysis_enabled else None, "analysis_report": str(self.results_dir / 'report.html') if self.analysis_enabled else None}
        if self.analysis_enabled and self.checksums_file is not None:
            atomic_write_json(self.checksums_file.parent / 'task_results.json', summary)
        self._cleanup_partial_dir()
        self._print_summary(summary)
        return summary
