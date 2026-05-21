from __future__ import annotations

import html
import json
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .models import AnalysisResult, ArtifactRecord
from ..core.utils import (
    CommandResult,
    atomic_write_json,
    atomic_write_text,
    compute_hashes,
    detect_mp4_appended_data,
    ensure_dirs,
    extract_printable_strings,
    hex_preview,
    is_media_file,
    is_subtitle_file,
    list_files,
    run_command,
    safe_stem,
    search_keywords_file,
    search_keywords_text,
    tail_bytes,
)




class AnalyzerProbeOpsMixin:
    def _make_output_dir(self, media_path: Path) -> Path:
        digest = "nohash"
        try:
            digest = compute_hashes(media_path)["sha256"][:12]
        except Exception:
            pass
        return self.output_root / f"{safe_stem(media_path)}_{digest}"

    def _warn(self, result: AnalysisResult, message: str) -> None:
        self.logger.warning("%s: %s", Path(result.input_file).name, message)
        result.warnings.append(message)

    def _err(self, result: AnalysisResult, message: str) -> None:
        self.logger.error("%s: %s", Path(result.input_file).name, message)
        result.errors.append(message)

    def _save_command(self, name: str, cmd_result: CommandResult, out_dir: Path, result: AnalysisResult, suffix: str = "txt") -> None:
        result.command_results[name] = cmd_result.to_dict()
        text = "COMMAND: " + " ".join(cmd_result.command) + "\n"
        text += f"RETURNCODE: {cmd_result.returncode}\nTIMED_OUT: {cmd_result.timed_out}\n\n"
        text += "--- STDOUT ---\n" + cmd_result.stdout + "\n\n--- STDERR ---\n" + cmd_result.stderr + "\n"
        output = out_dir / f"{name}.{suffix}"
        atomic_write_text(output, text)
        result.artifacts.append(ArtifactRecord(str(output), name))

    def _ffprobe(self, media_path: Path, out_dir: Path, result: AnalysisResult) -> None:
        if not self.tools.get("ffprobe"):
            self._warn(result, "ffprobe not found; skipped container metadata")
            return
        cmd = ["ffprobe", "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", str(media_path)]
        cr = run_command(cmd, timeout=self.timeout, logger=self.logger)
        self._save_command("ffprobe_raw", cr, out_dir, result)
        if cr.returncode == 0 and cr.stdout.strip():
            try:
                parsed = json.loads(cr.stdout)
                atomic_write_json(out_dir / "ffprobe.json", parsed)
                result.metadata["ffprobe"] = self._summarize_ffprobe(parsed)
                result.artifacts.append(ArtifactRecord(str(out_dir / "ffprobe.json"), "ffprobe-json"))
            except json.JSONDecodeError as exc:
                self._warn(result, f"ffprobe JSON parse failed: {exc}")
        else:
            self._warn(result, "ffprobe returned non-zero status")

        # Also exercise ffmpeg-python's wrapper. It calls ffprobe underneath and
        # provides a Python-native dictionary that is handy for downstream code.
        try:
            import ffmpeg  # type: ignore
            probed = ffmpeg.probe(str(media_path))
            atomic_write_json(out_dir / "ffmpeg_python_probe.json", probed)
            result.artifacts.append(ArtifactRecord(str(out_dir / "ffmpeg_python_probe.json"), "ffmpeg-python-probe"))
        except Exception as exc:
            self._warn(result, f"ffmpeg-python probe failed: {exc}")

    @staticmethod
    def _summarize_ffprobe(parsed: Mapping[str, Any]) -> Dict[str, Any]:
        summary: Dict[str, Any] = {}
        fmt = parsed.get("format", {}) or {}
        summary["format_name"] = fmt.get("format_name")
        summary["duration"] = fmt.get("duration")
        summary["size"] = fmt.get("size")
        summary["bit_rate"] = fmt.get("bit_rate")
        streams = []
        for s in parsed.get("streams", []) or []:
            entry = {
                "index": s.get("index"),
                "codec_type": s.get("codec_type"),
                "codec_name": s.get("codec_name"),
                "width": s.get("width"),
                "height": s.get("height"),
                "r_frame_rate": s.get("r_frame_rate"),
                "avg_frame_rate": s.get("avg_frame_rate"),
                "bit_rate": s.get("bit_rate"),
                "channels": s.get("channels"),
                "sample_rate": s.get("sample_rate"),
            }
            streams.append({k: v for k, v in entry.items() if v is not None})
        summary["streams"] = streams
        return summary

    def _exiftool(self, media_path: Path, out_dir: Path, result: AnalysisResult) -> None:
        if not self.tools.get("exiftool"):
            self._warn(result, "exiftool not found; skipped EXIF/XMP/ICC metadata")
            return
        cmd = ["exiftool", "-json", "-a", "-u", "-g1", str(media_path)]
        cr = run_command(cmd, timeout=self.timeout, logger=self.logger)
        self._save_command("exiftool_raw", cr, out_dir, result)
        if cr.returncode == 0 and cr.stdout.strip():
            try:
                parsed = json.loads(cr.stdout)
                atomic_write_json(out_dir / "exiftool.json", parsed)
                result.metadata["exiftool_keys"] = list(parsed[0].keys())[:200] if parsed else []
                result.artifacts.append(ArtifactRecord(str(out_dir / "exiftool.json"), "exiftool-json"))
            except json.JSONDecodeError as exc:
                self._warn(result, f"exiftool JSON parse failed: {exc}")
        else:
            self._warn(result, "exiftool returned non-zero status")

    def _binwalk(self, media_path: Path, out_dir: Path, result: AnalysisResult) -> None:
        if not self.tools.get("binwalk"):
            self._warn(result, "binwalk not found; skipped file-structure scan")
            return
        cmd = ["binwalk", str(media_path)]
        if self.analysis_config.get("binwalk_extract", False):
            extract_dir = out_dir / "binwalk_extract"
            ensure_dirs(extract_dir)
            cmd = ["binwalk", "-e", "-M", "--directory", str(extract_dir), str(media_path)]
        cr = run_command(cmd, timeout=self.timeout, logger=self.logger)
        self._save_command("binwalk", cr, out_dir, result)
        hits = search_keywords_text(cr.stdout + "\n" + cr.stderr, self.keywords)
        if hits:
            result.keyword_hits["binwalk"] = hits

