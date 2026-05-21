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




class AnalyzerTextOpsMixin:
    def _strings(self, media_path: Path, out_dir: Path, result: AnalysisResult) -> None:
        min_len = int(self.analysis_config.get("strings_min_length", 4))
        strings_file = out_dir / "strings.txt"
        if self.tools.get("strings"):
            cmd = ["strings", "-a", "-n", str(min_len), str(media_path)]
            cr = run_command(cmd, timeout=self.timeout, logger=self.logger)
            self._save_command("strings_command", cr, out_dir, result)
            if cr.stdout:
                atomic_write_text(strings_file, cr.stdout)
            elif cr.returncode != 0:
                self._warn(result, "system strings failed; falling back to Python extractor")
                atomic_write_text(strings_file, "\n".join(extract_printable_strings(media_path, min_len)))
        else:
            atomic_write_text(strings_file, "\n".join(extract_printable_strings(media_path, min_len)))
        result.artifacts.append(ArtifactRecord(str(strings_file), "strings"))
        text = strings_file.read_text(encoding="utf-8", errors="replace")
        hits = search_keywords_text(text, self.keywords)
        if hits:
            result.keyword_hits["strings"] = hits[:500]
            atomic_write_json(out_dir / "keyword_hits_strings.json", hits[:500])
            result.artifacts.append(ArtifactRecord(str(out_dir / "keyword_hits_strings.json"), "keyword-hits"))

    def _tail_scan(self, media_path: Path, out_dir: Path, result: AnalysisResult) -> None:
        scan_bytes = int(self.analysis_config.get("tail_scan_bytes", 262144))
        tail = tail_bytes(media_path, scan_bytes)
        tail_file = out_dir / "tail.bin"
        tail_file.write_bytes(tail)
        result.artifacts.append(ArtifactRecord(str(tail_file), "tail-bytes", f"last {len(tail)} bytes"))
        hits = search_keywords_text(tail.decode("utf-8", errors="replace"), self.keywords)
        if hits:
            result.keyword_hits["tail"] = hits
        tail_meta: Dict[str, Any] = {
            "scanned_bytes": len(tail),
            "hex_preview": hex_preview(tail),
            "keyword_hits": hits,
        }
        if media_path.suffix.lower() in {".mp4", ".m4v", ".mov"}:
            mp4_tail = detect_mp4_appended_data(media_path)
            tail_meta["mp4_appended_data"] = mp4_tail
            appended_bytes = int(mp4_tail.get("appended_bytes") or 0)
            last_box_end = mp4_tail.get("last_box_end")
            if appended_bytes and last_box_end:
                with media_path.open("rb") as f:
                    f.seek(int(last_box_end))
                    appended = f.read(min(appended_bytes, 50 * 1024 * 1024))
                appended_file = out_dir / "appended_after_last_mp4_box.bin"
                appended_file.write_bytes(appended)
                result.artifacts.append(ArtifactRecord(str(appended_file), "appended-data", f"{appended_bytes} bytes after last MP4 box"))
                self._warn(result, f"possible appended data after last MP4 box: {appended_bytes} bytes")
        atomic_write_json(out_dir / "tail_scan.json", tail_meta)
        result.artifacts.append(ArtifactRecord(str(out_dir / "tail_scan.json"), "tail-scan-json"))

    def _comments_from_infojson(self, media_path: Path, out_dir: Path, result: AnalysisResult) -> None:
        candidates = list(media_path.parent.glob(f"{media_path.stem}*.info.json"))
        if not candidates:
            candidates = sorted(media_path.parent.glob("*.info.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:3]
        for info in candidates[:3]:
            try:
                data = json.loads(info.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue
            comments = data.get("comments") or []
            if comments:
                lines = []
                for c in comments:
                    if isinstance(c, dict):
                        lines.append(f"[{c.get('timestamp') or ''}] {c.get('author') or ''}: {c.get('text') or ''}")
                    else:
                        lines.append(str(c))
                text = "\n".join(lines)
                out = out_dir / "comments.txt"
                atomic_write_text(out, text)
                result.artifacts.append(ArtifactRecord(str(out), "comments"))
                hits = search_keywords_text(text, self.keywords)
                if hits:
                    result.keyword_hits["comments"] = hits[:500]
                return

    def _subtitle_keyword_scan(self, media_path: Path, out_dir: Path, result: AnalysisResult, subtitle_roots: Optional[Iterable[Path]]) -> None:
        roots = {media_path.parent}
        for root in subtitle_roots or []:
            roots.add(Path(root))
        subtitle_files: List[Path] = []
        for root in roots:
            if not root.exists():
                continue
            for p in root.rglob("*"):
                if p.is_file() and is_subtitle_file(p):
                    # Prefer same-stem siblings but do not over-filter playlist files.
                    if media_path.stem in p.stem or p.parent == media_path.parent:
                        subtitle_files.append(p)
        aggregate_hits: List[Dict[str, Any]] = []
        copied = []
        subtitles_dir = out_dir / "subtitles"
        ensure_dirs(subtitles_dir)
        for sub in sorted(set(subtitle_files)):
            try:
                text = sub.read_text(encoding="utf-8", errors="replace")
                hits = search_keywords_text(text, self.keywords)
                if hits:
                    for h in hits:
                        h["file"] = str(sub)
                    aggregate_hits.extend(hits)
                target = subtitles_dir / sub.name
                target.write_text(text, encoding="utf-8")
                copied.append(str(target))
            except Exception as exc:
                self._warn(result, f"subtitle scan failed for {sub}: {exc}")
        if copied:
            result.artifacts.append(ArtifactRecord(str(subtitles_dir), "subtitles", f"{len(copied)} subtitle files copied"))
        if aggregate_hits:
            result.keyword_hits["subtitles"] = aggregate_hits[:500]
            atomic_write_json(out_dir / "keyword_hits_subtitles.json", aggregate_hits[:500])
            result.artifacts.append(ArtifactRecord(str(out_dir / "keyword_hits_subtitles.json"), "subtitle-keyword-hits"))

