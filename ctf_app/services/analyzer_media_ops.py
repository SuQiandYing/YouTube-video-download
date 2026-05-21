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



class AnalyzerMediaOpsMixin:
    def _extract_keyframes(self, media_path: Path, out_dir: Path, result: AnalysisResult) -> None:
        if not self.tools.get("ffmpeg"):
            self._warn(result, "ffmpeg not found; skipped keyframe extraction")
            return
        key_dir = out_dir / "keyframes"
        ensure_dirs(key_dir)
        max_frames = int(self.analysis_config.get("max_keyframes", 150))
        # -skip_frame nokey extracts I-frames. -vframes caps output to keep large playlists manageable.
        cmd = [
            self.ffmpeg_cmd or "ffmpeg", "-hide_banner", "-y", "-skip_frame", "nokey", "-i", str(media_path),
            "-vsync", "vfr", "-vframes", str(max_frames), str(key_dir / "keyframe_%06d.png"),
        ]
        cr = run_command(cmd, timeout=self.timeout, logger=self.logger)
        self._save_command("ffmpeg_keyframes", cr, out_dir, result)
        frames = sorted(key_dir.glob("*.png"))
        result.metadata["keyframes_extracted"] = len(frames)
        if frames:
            result.artifacts.append(ArtifactRecord(str(key_dir), "keyframes", f"{len(frames)} PNG keyframes"))
        elif cr.returncode != 0:
            self._warn(result, "keyframe extraction returned no PNG files")

    def _audio_and_spectrogram(self, media_path: Path, out_dir: Path, result: AnalysisResult) -> None:
        if not self.tools.get("ffmpeg"):
            self._warn(result, "ffmpeg not found; skipped audio extraction/spectrogram")
            return
        audio_dir = out_dir / "audio"
        ensure_dirs(audio_dir)
        wav = audio_dir / "audio.wav"
        cmd_extract = [self.ffmpeg_cmd or "ffmpeg", "-hide_banner", "-y", "-i", str(media_path), "-vn", "-acodec", "pcm_s16le", "-ar", "44100", "-ac", "2", str(wav)]
        cr_extract = run_command(cmd_extract, timeout=self.timeout, logger=self.logger)
        self._save_command("ffmpeg_audio_extract", cr_extract, out_dir, result)
        if cr_extract.returncode != 0 or not wav.exists() or wav.stat().st_size == 0:
            self._warn(result, "audio extraction failed or no audio stream was present")
            return
        result.artifacts.append(ArtifactRecord(str(wav), "audio-wav"))
        spectrogram = audio_dir / "spectrogram.png"
        cmd_spec = [
            self.ffmpeg_cmd or "ffmpeg", "-hide_banner", "-y", "-i", str(wav),
            "-lavfi", "showspectrumpic=s=1920x1080:legend=1:scale=log",
            str(spectrogram),
        ]
        cr_spec = run_command(cmd_spec, timeout=self.timeout, logger=self.logger)
        self._save_command("ffmpeg_spectrogram", cr_spec, out_dir, result)
        if spectrogram.exists() and spectrogram.stat().st_size > 0:
            result.artifacts.append(ArtifactRecord(str(spectrogram), "spectrogram"))
        else:
            self._warn(result, "spectrogram generation failed")

    def _run_zsteg(self, out_dir: Path, result: AnalysisResult) -> None:
        if not self.tools.get("zsteg"):
            self._warn(result, "zsteg not found; skipped PNG LSB scan")
            return
        key_dir = out_dir / "keyframes"
        frames = sorted(key_dir.glob("*.png"))
        if not frames:
            return
        max_frames = int(self.analysis_config.get("max_zsteg_frames", 80))
        zsteg_dir = out_dir / "zsteg"
        ensure_dirs(zsteg_dir)
        aggregate_hits: List[Dict[str, Any]] = []
        for frame in frames[:max_frames]:
            cmd = ["zsteg", "-a", str(frame)]
            cr = run_command(cmd, timeout=min(self.timeout, 90), logger=self.logger)
            out = zsteg_dir / f"{frame.stem}.zsteg.txt"
            atomic_write_text(out, "COMMAND: " + " ".join(cr.command) + "\n\n" + cr.stdout + "\n" + cr.stderr)
            hits = search_keywords_text(cr.stdout + "\n" + cr.stderr, self.keywords)
            if hits:
                for h in hits:
                    h["frame"] = str(frame)
                aggregate_hits.extend(hits)
        result.artifacts.append(ArtifactRecord(str(zsteg_dir), "zsteg", f"scanned {min(len(frames), max_frames)} PNG frames"))
        if aggregate_hits:
            result.keyword_hits["zsteg"] = aggregate_hits[:500]
            atomic_write_json(out_dir / "keyword_hits_zsteg.json", aggregate_hits[:500])
            result.artifacts.append(ArtifactRecord(str(out_dir / "keyword_hits_zsteg.json"), "zsteg-keyword-hits"))

    def _write_single_html_report(self, result: AnalysisResult) -> None:
        report = Path(result.output_dir) / "report.html"
        html_doc = self._render_html([result], title=f"Forensic Report - {Path(result.input_file).name}")
        atomic_write_text(report, html_doc)
        result.artifacts.append(ArtifactRecord(str(report), "html-report"))

    def write_global_report(self, results: List[AnalysisResult]) -> None:
        ensure_dirs(self.output_root)
        atomic_write_json(self.output_root / "analysis_summary.json", [r.to_dict() for r in results])
        atomic_write_text(self.output_root / "report.html", self._render_html(results, title="ctf_ytdl_forensics Report"))

