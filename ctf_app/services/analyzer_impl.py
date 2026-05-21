# FOR CTF & SECURITY RESEARCH USE ONLY
"""
Forensic preprocessing module for ctf_ytdl_forensics.

Authorized CTF / security research use only. This module runs metadata, string,
container, keyframe, audio-spectrum and LSB-oriented preprocessing steps against
locally available media files.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from .analyzer_helpers import AnalyzerHelperMixin
from .models import AnalysisResult, ArtifactRecord
from ..core.utils import (
    MEDIA_EXTENSIONS,
    SUBTITLE_EXTENSIONS,
    atomic_write_json,
    check_external_tools,
    compute_hashes,
    ensure_dirs,
    is_media_file,
)


class ForensicAnalyzer(AnalyzerHelperMixin):
    def __init__(self, config: Mapping[str, Any], logger: Optional[logging.Logger] = None):
        self.config = dict(config)
        self.analysis_config = self.config.get("analysis", {})
        self.keywords = self.config.get("keywords", []) or []
        self.logger = logger or logging.getLogger("ctf_ytdl_forensics.analyzer")
        self.output_root = Path(self.analysis_config.get("output_dir", "./analysis_results"))
        ensure_dirs(self.output_root)
        self.timeout = int(self.analysis_config.get("command_timeout", 180))
        self.tools = check_external_tools(["ffmpeg", "ffprobe", "exiftool", "binwalk", "strings", "zsteg"], self.logger)
        self.ffmpeg_cmd = self._resolve_ffmpeg_cmd()
        if self.ffmpeg_cmd:
            self.tools["ffmpeg"] = True

    def _resolve_ffmpeg_cmd(self) -> str:
        exe = shutil.which("ffmpeg")
        if exe:
            return exe
        try:
            import imageio_ffmpeg  # type: ignore
            exe = imageio_ffmpeg.get_ffmpeg_exe()
            self.logger.info("Using bundled imageio-ffmpeg binary: %s", exe)
            return str(exe)
        except Exception:
            return ""

    def analyze_many(self, files: Iterable[Path], subtitle_roots: Optional[Iterable[Path]] = None) -> List[AnalysisResult]:
        media_files = [Path(f) for f in files if Path(f).exists() and is_media_file(f)]
        results: List[AnalysisResult] = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            transient=False,
        ) as progress:
            task = progress.add_task("forensic preprocessing", total=max(len(media_files), 1))
            for media in media_files:
                progress.update(task, description=f"analyzing {media.name}")
                try:
                    results.append(self.analyze_file(media, subtitle_roots=subtitle_roots))
                except Exception as exc:  # pragma: no cover - keep batch alive
                    self.logger.exception("Analysis failed for %s", media)
                    out_dir = self._make_output_dir(media)
                    results.append(AnalysisResult(str(media), str(out_dir), errors=[str(exc)]))
                finally:
                    progress.advance(task)
        self.write_global_report(results)
        return results

    def analyze_file(self, media_path: Path, subtitle_roots: Optional[Iterable[Path]] = None) -> AnalysisResult:
        media_path = Path(media_path).resolve()
        out_dir = self._make_output_dir(media_path)
        ensure_dirs(out_dir)
        result = AnalysisResult(input_file=str(media_path), output_dir=str(out_dir))
        self.logger.info("Analyzing: %s", media_path)

        try:
            result.hashes = compute_hashes(media_path)
            atomic_write_json(out_dir / "hashes.json", result.hashes)
            result.artifacts.append(ArtifactRecord(str(out_dir / "hashes.json"), "hashes"))
        except Exception as exc:
            self._warn(result, f"hash computation failed: {exc}")

        self._ffprobe(media_path, out_dir, result)
        if self.analysis_config.get("run_exiftool", True):
            self._exiftool(media_path, out_dir, result)
        if self.analysis_config.get("run_binwalk", True):
            self._binwalk(media_path, out_dir, result)
        self._strings(media_path, out_dir, result)
        self._tail_scan(media_path, out_dir, result)
        self._comments_from_infojson(media_path, out_dir, result)
        self._subtitle_keyword_scan(media_path, out_dir, result, subtitle_roots=subtitle_roots)

        if self.analysis_config.get("extract_keyframes", True) and media_path.suffix.lower() not in {".mp3", ".wav", ".flac", ".m4a", ".aac", ".opus", ".ogg"}:
            self._extract_keyframes(media_path, out_dir, result)
        if self.analysis_config.get("generate_spectrogram", True):
            self._audio_and_spectrogram(media_path, out_dir, result)
        if self.analysis_config.get("run_zsteg", True):
            self._run_zsteg(out_dir, result)

        atomic_write_json(out_dir / "analysis.json", result.to_dict())
        result.artifacts.append(ArtifactRecord(str(out_dir / "analysis.json"), "json-summary"))
        self._write_single_html_report(result)
        return result

def main() -> None:
    import argparse
    from ..core.utils import load_config, setup_logging

    parser = argparse.ArgumentParser(description="Run ctf_ytdl_forensics analysis on local media files.")
    parser.add_argument("files", nargs="+", help="Media files to analyze")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--output-dir", help="Override analysis output directory")
    args = parser.parse_args()
    cfg = load_config(args.config)
    if args.output_dir:
        cfg.setdefault("analysis", {})["output_dir"] = args.output_dir
    logger, _ = setup_logging(cfg.get("logging", {}).get("level", "INFO"))
    analyzer = ForensicAnalyzer(cfg, logger=logger)
    analyzer.analyze_many([Path(f) for f in args.files], subtitle_roots=[Path(cfg.get("download", {}).get("output_dir", "./challenge_videos"))])


if __name__ == "__main__":
    main()
