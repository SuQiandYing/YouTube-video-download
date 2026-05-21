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



class AnalyzerReportingMixin:
    def _render_html(self, results: List[AnalysisResult], title: str) -> str:
        def esc(x: Any) -> str:
            return html.escape(str(x))

        cards = []
        for r in results:
            meta = esc(json.dumps(r.metadata, ensure_ascii=False, indent=2))
            hashes = esc(json.dumps(r.hashes, ensure_ascii=False, indent=2))
            hits = esc(json.dumps(r.keyword_hits, ensure_ascii=False, indent=2))
            warnings = "".join(f"<li>{esc(w)}</li>" for w in r.warnings) or "<li>None</li>"
            errors = "".join(f"<li>{esc(e)}</li>" for e in r.errors) or "<li>None</li>"
            artifacts = "".join(
                f"<li><code>{esc(a.kind)}</code>: {esc(a.path)} {(' - ' + esc(a.note)) if a.note else ''}</li>"
                for a in r.artifacts
            ) or "<li>None</li>"
            cards.append(f"""
<section class="card">
  <h2>{esc(Path(r.input_file).name)}</h2>
  <p><b>Input:</b> <code>{esc(r.input_file)}</code></p>
  <p><b>Output:</b> <code>{esc(r.output_dir)}</code></p>
  <h3>Hashes</h3><pre>{hashes}</pre>
  <h3>Container / Metadata Summary</h3><pre>{meta}</pre>
  <h3>Keyword Hits</h3><pre>{hits}</pre>
  <h3>Warnings</h3><ul>{warnings}</ul>
  <h3>Errors</h3><ul>{errors}</ul>
  <h3>Artifacts</h3><ul>{artifacts}</ul>
</section>""")
        return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin: 2rem; line-height: 1.45; }}
.banner {{ padding: .9rem 1rem; border: 2px solid #b58900; border-radius: 12px; background: rgba(181,137,0,.12); }}
.card {{ border: 1px solid #9995; border-radius: 16px; padding: 1rem 1.2rem; margin: 1rem 0; box-shadow: 0 2px 12px #0001; }}
pre {{ overflow-x: auto; padding: 1rem; border-radius: 12px; background: #00000012; }}
code {{ word-break: break-all; }}
h1, h2, h3 {{ line-height: 1.2; }}
</style>
</head>
<body>
<h1>{esc(title)}</h1>
<p class="banner"><b>FOR CTF &amp; SECURITY RESEARCH USE ONLY.</b> Authorized CTF, security research and teaching use only. Do not use to scrape, pirate, bypass DRM, or violate service terms, robots.txt, or law.</p>
{''.join(cards)}
</body>
</html>"""



