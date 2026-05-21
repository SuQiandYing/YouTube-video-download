from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.progress import TaskID

from ..core.utils import compute_hashes, should_auto_disable_proxy


class DownloaderRuntimeEnvMixin:
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

    def _ensure_ejs_options(self, opts: Dict[str, Any]) -> None:
        opts["js_runtimes"] = self._detect_js_runtimes()
        opts["remote_components"] = {"ejs:github"}

    def _select_proxy(self) -> Optional[str]:
        if getattr(self.args, "no_proxy", False):
            return None
        proxy = self.args.proxy
        if not proxy:
            proxy_cfg = self.config.get("proxy", {}) or {}
            if not proxy_cfg.get("enabled", False):
                return None
            proxy = proxy_cfg.get("https") or proxy_cfg.get("http")
        proxy = str(proxy or "").strip()
        if not proxy:
            return None
        proxy_cfg = self.config.get("proxy", {}) or {}
        if proxy_cfg.get("auto_disable_if_unreachable", True) and should_auto_disable_proxy(proxy):
            self.logger.warning("Proxy %s is unreachable; disabled automatically. Start your proxy app or pass --proxy explicitly after it is running.", proxy)
            return None
        return proxy

    def _sub_langs(self) -> List[str]:
        raw = self.args.sub_langs or self.download_cfg.get("subtitles_langs", ["all"])
        langs = [x.strip() for x in raw.split(",")] if isinstance(raw, str) else list(raw)
        if any(str(lang).strip().lower() in {"0", "false", "no", "none", "off", "disable", "disabled"} for lang in langs):
            return []
        return [lang for lang in langs if str(lang).strip()] or ["all"]

    def _subtitles_requested(self) -> bool:
        return bool(self._sub_langs())

    def _create_progress_task(self, url: str) -> TaskID:
        if self.progress is None:
            return TaskID(0)
        label = url[:70] + ("..." if len(url) > 70 else "")
        with self.lock:
            task_id = self.progress.add_task(label, total=None)
            self.task_ids[url] = task_id
            return task_id

    def _make_progress_hook(self, url: str, task_id: TaskID):
        def hook(d: Dict[str, Any]) -> None:
            if self.progress is None:
                return
            status = d.get("status")
            filename = Path(d.get("filename") or d.get("tmpfilename") or "download").name
            total = d.get("total_bytes") or d.get("total_bytes_estimate")
            downloaded = d.get("downloaded_bytes") or 0
            with self.lock:
                if status == "downloading":
                    self.progress.update(task_id, total=total, completed=downloaded, description=f"downloading {filename[:54]}")
                elif status == "finished":
                    self.progress.update(task_id, total=total, completed=total if total else downloaded, description=f"post-processing {filename[:54]}")
                elif status == "error":
                    self.progress.update(task_id, description=f"failed {filename[:54]}")
        return hook

    def _hash_downloaded_files(self, files):
        records = {}
        for f in sorted(set(files)):
            p = Path(f)
            if not p.exists() or p.name.endswith(".part"):
                continue
            try:
                rel = str(p.relative_to(self.output_dir.resolve())) if p.is_relative_to(self.output_dir.resolve()) else str(p)
            except Exception:
                rel = str(p)
            try:
                records[rel] = compute_hashes(p)
            except Exception as exc:
                self.logger.warning("Failed to hash %s: %s", p, exc)
        return records
