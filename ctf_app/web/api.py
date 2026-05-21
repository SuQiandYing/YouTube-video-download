from __future__ import annotations

import argparse
import json
import locale
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ..core.utils import load_config
from ..browser import probe as probe_browser_cookies
from ..services.downloader import probe_target_info


ROOT_DIR = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT_DIR / "config.yaml"


def get_app_config() -> Dict[str, Any]:
    return load_config(CONFIG_PATH)


def get_web_defaults() -> Dict[str, Any]:
    cfg = get_app_config()
    download_cfg = dict(cfg.get("download", {}))
    analysis_cfg = dict(cfg.get("analysis", {}))
    return {
        "quality": str(download_cfg.get("quality", "best") or "best"),
        "output_dir": str(download_cfg.get("output_dir", "") or ""),
        "audio_format": str(download_cfg.get("audio_format", "source") or "source"),
        "merge_output_format": str(download_cfg.get("merge_output_format", "mp4") or "mp4"),
        "no_analysis": not bool(analysis_cfg.get("enabled", True)),
        "cookie_mode": "file",
    }


def detect_cookie_files() -> List[str]:
    candidates: List[Path] = []
    seen: set[str] = set()
    home = Path.home()

    direct_dirs = [
        ROOT_DIR,
        ROOT_DIR / "challenge_videos",
        home / "Downloads",
        home / "Desktop",
        home / "Documents",
    ]
    direct_names = [
        "cookies.txt",
        "www.youtube.com_cookies.txt",
        "youtube_cookies.txt",
    ]

    def push(path: Path) -> None:
        if not path.exists() or not path.is_file():
            return
        resolved = str(path.resolve())
        if resolved in seen:
            return
        seen.add(resolved)
        candidates.append(path.resolve())

    for root in direct_dirs:
        if not root.exists():
            continue
        for name in direct_names:
            push(root / name)
        for path in root.glob("*cookies*.txt"):
            push(path)
        for path in root.glob("*youtube*.txt"):
            push(path)

    candidates.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
    return [str(path) for path in candidates[:20]]


class ProbeRequest(BaseModel):
    url: str
    playlist: bool = False
    quality: str = "best"
    audio_only: bool = False
    cookies: Optional[str] = None
    cookies_from_browser: Optional[str] = None


class DownloadRequest(BaseModel):
    urls: List[str] = Field(default_factory=list)
    quality: str = "best"
    audio_only: bool = False
    audio_format: str = "source"
    merge_output_format: str = "mp4"
    cookies: Optional[str] = None
    cookies_from_browser: Optional[str] = None
    output_dir: Optional[str] = None
    no_analysis: bool = True
    concurrent: int = 1
    retry: int = 3
    timeout: int = 30


@dataclass
class WebTask:
    id: str
    title: str
    urls: List[str]
    status: str = "queued"
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    returncode: Optional[int] = None
    log_lines: List[str] = field(default_factory=list)
    process: Optional[subprocess.Popen[str]] = None
    temp_targets_file: Optional[str] = None

    def as_response(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "urls": list(self.urls),
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "returncode": self.returncode,
            "temp_targets_file": self.temp_targets_file,
            "log": "".join(self.log_lines[-200:]),
        }


TASKS: Dict[str, WebTask] = {}
TASK_LOCK = threading.Lock()


def build_namespace(req: ProbeRequest, cfg: Dict[str, Any]) -> argparse.Namespace:
    download_cfg = dict(cfg.get("download", {}))
    analysis_cfg = dict(cfg.get("analysis", {}))
    return argparse.Namespace(
        url=None,
        targets=None,
        playlist=req.playlist,
        quality=req.quality,
        audio_only=req.audio_only,
        audio_format="source",
        section=None,
        sub_langs="none",
        cookies=req.cookies,
        cookies_from_browser=req.cookies_from_browser,
        proxy=None,
        no_proxy=False,
        limit_rate=None,
        concurrent=1,
        concurrent_fragments=1,
        retry=1,
        timeout=30,
        expected_hashes=None,
        output_dir=download_cfg.get("output_dir"),
        results_dir=analysis_cfg.get("output_dir"),
        config=str(CONFIG_PATH),
        no_analysis=not bool(analysis_cfg.get("enabled", True)),
        log_level="INFO",
        check_robots=False,
    )


def parse_probe_response(info: Dict[str, Any], requested_url: str) -> Dict[str, Any]:
    if info.get("_type") == "playlist":
        entries = [item for item in (info.get("entries") or []) if isinstance(item, dict)]
        return {
            "kind": "playlist",
            "url": requested_url,
            "title": info.get("title") or requested_url,
            "uploader": info.get("uploader") or info.get("channel") or "",
            "thumbnail": info.get("thumbnail") or "",
            "entry_count": len(entries),
            "entries": [
                {
                    "id": str(item.get("id") or ""),
                    "title": str(item.get("title") or ""),
                    "duration": item.get("duration"),
                    "thumbnail": item.get("thumbnail") or "",
                }
                for item in entries[:50]
            ],
        }
    formats = [item for item in (info.get("formats") or []) if isinstance(item, dict)]
    return {
        "kind": "video",
        "url": requested_url,
        "title": info.get("title") or requested_url,
        "uploader": info.get("uploader") or info.get("channel") or "",
        "thumbnail": info.get("thumbnail") or "",
        "duration": info.get("duration"),
        "formats": [
            {
                "format_id": str(item.get("format_id") or ""),
                "ext": item.get("ext"),
                "resolution": item.get("resolution") or (f"{item.get('width')}x{item.get('height')}" if item.get("width") and item.get("height") else ""),
                "width": item.get("width"),
                "height": item.get("height"),
                "vcodec": item.get("vcodec"),
                "acodec": item.get("acodec"),
                "fps": item.get("fps"),
                "tbr": item.get("tbr"),
                "vbr": item.get("vbr"),
                "abr": item.get("abr"),
                "asr": item.get("asr"),
                "audio_channels": item.get("audio_channels"),
                "format_note": item.get("format_note"),
                "protocol": item.get("protocol"),
                "dynamic_range": item.get("dynamic_range"),
                "filesize": item.get("filesize") or item.get("filesize_approx"),
            }
            for item in formats[:200]
        ],
    }


def build_download_command(req: DownloadRequest, cfg: Dict[str, Any]) -> tuple[list[str], Optional[str]]:
    download_cfg = dict(cfg.get("download", {}))
    cmd = [
        sys.executable,
        "-m",
        "ctf_app.launchers.downloader_cli",
        "--quality",
        req.quality or "best",
        "--concurrent",
        str(max(1, req.concurrent)),
        "--retry",
        str(max(1, req.retry)),
        "--timeout",
        str(max(1, req.timeout)),
    ]
    effective_output_dir = req.output_dir or download_cfg.get("output_dir")
    if effective_output_dir:
        cmd.extend(["--output-dir", str(effective_output_dir)])
    if req.audio_only:
        cmd.extend(["--audio-only", "--audio-format", req.audio_format or "source"])
    elif req.merge_output_format:
        cmd.extend(["--merge-output-format", req.merge_output_format])
    if req.no_analysis:
        cmd.append("--no-analysis")
    if req.cookies:
        cmd.extend(["--cookies", req.cookies])
    if req.cookies_from_browser:
        cmd.extend(["--cookies-from-browser", req.cookies_from_browser])
    if len(req.urls) == 1:
        cmd.append(req.urls[0])
        return cmd, None
    tmp = tempfile.NamedTemporaryFile(prefix="ctf_urls_", suffix=".txt", delete=False, encoding="utf-8")
    try:
        tmp.write("\n".join(req.urls))
        tmp.flush()
    finally:
        tmp.close()
    cmd.extend(["--targets", tmp.name])
    return cmd, tmp.name


def run_task(task_id: str, cmd: list[str]) -> None:
    with TASK_LOCK:
        task = TASKS[task_id]
        task.status = "running"
    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        encoding=locale.getpreferredencoding(False) or "utf-8",
        errors="replace",
        bufsize=1,
    )
    with TASK_LOCK:
        TASKS[task_id].process = proc
    assert proc.stdout is not None
    for line in proc.stdout:
        with TASK_LOCK:
            TASKS[task_id].log_lines.append(line)
    rc = proc.wait()
    with TASK_LOCK:
        task = TASKS[task_id]
        task.returncode = rc
        task.finished_at = time.time()
        task.status = "completed" if rc == 0 else ("stopped" if rc < 0 else "error")
        task.process = None
        if task.temp_targets_file:
            try:
                Path(task.temp_targets_file).unlink(missing_ok=True)
            except Exception:
                pass


app = FastAPI(title="ctf_ytdl_forensics Web API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/api/defaults")
def defaults() -> Dict[str, Any]:
    return get_web_defaults()


@app.get("/api/browser-cookies")
def list_browser_cookies() -> Dict[str, Any]:
    results = probe_browser_cookies()
    return {
        "profiles": results,
        "recommended": next((item for item in results if int(item.get("youtube_cookie_rows") or 0) > 0), None),
    }


@app.get("/api/cookie-files")
def list_cookie_files() -> Dict[str, Any]:
    files = detect_cookie_files()
    return {
        "files": files,
        "recommended": files[0] if files else None,
    }


@app.post("/api/probe")
def probe(req: ProbeRequest) -> Dict[str, Any]:
    cfg = get_app_config()
    args = build_namespace(req, cfg)
    import logging

    logger = logging.getLogger("ctf_ytdl_forensics.webapi")
    try:
        info = probe_target_info(cfg, args, logger, req.url, playlist=req.playlist)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return parse_probe_response(info, req.url)


@app.post("/api/downloads")
def start_download(req: DownloadRequest) -> Dict[str, Any]:
    urls = [item.strip() for item in req.urls if item.strip()]
    if not urls:
        raise HTTPException(status_code=400, detail="No URLs provided")
    cfg = get_app_config()
    cmd, temp_targets = build_download_command(req, cfg)
    task_id = uuid.uuid4().hex[:12]
    task = WebTask(id=task_id, title=urls[0], urls=urls, temp_targets_file=temp_targets)
    with TASK_LOCK:
        TASKS[task_id] = task
    threading.Thread(target=run_task, args=(task_id, cmd), daemon=True).start()
    return {"task_id": task_id}


@app.get("/api/tasks")
def list_tasks() -> Dict[str, Any]:
    with TASK_LOCK:
        return {"tasks": [task.as_response() for task in TASKS.values()]}


@app.post("/api/tasks/{task_id}/stop")
def stop_task(task_id: str) -> Dict[str, Any]:
    with TASK_LOCK:
        task = TASKS.get(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        proc = task.process
    if proc is None:
        return {"stopped": False}
    proc.terminate()
    return {"stopped": True}
