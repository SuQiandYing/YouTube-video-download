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



class DownloaderBrowserProfilesMixin:
    def _browser_cookie_candidates(self, browser_spec: str) -> List[Optional[str]]:
        if not browser_spec:
            return [None]
        if browser_spec.lower() != "auto":
            return [browser_spec]

        # Lazy mode: prefer the browser profiles on this machine that actually
        # contain youtube.com cookie rows. This fixes the common Windows case
        # where the user is logged in under Chrome "Profile 1" rather than
        # "Default". Only cookie metadata/name counts are inspected; values are
        # not decrypted, exported, or stored by this probe.
        discovered = self._discover_browser_cookie_profiles()
        if discovered:
            self.logger.info(
                "Auto browser-cookie order: %s",
                ", ".join(f"{spec}({count})" for spec, count in discovered),
            )

        # Important v5 fix: do NOT blindly try every supported browser. If
        # Vivaldi/Opera/etc. are not installed, yt-dlp raises misleading final
        # errors like "could not find vivaldi cookies database", hiding the real
        # YouTube authentication failure. Fallbacks are now limited to installed
        # browsers/profiles with an actual cookie database.
        fallback = self._installed_browser_cookie_candidates()
        candidates = self._dedupe_candidates([spec for spec, _count in discovered] + fallback)
        if not candidates:
            self.logger.warning("Auto browser-cookie mode found no local browser cookie databases")
            return [None]
        return candidates

    def _installed_browser_cookie_candidates(self) -> List[str]:
        candidates: List[str] = []
        for browser, root in self._candidate_browser_roots():
            profile_names: List[str] = []
            for profile_name, _cookie_db in self._iter_cookie_db_paths(root, browser):
                if profile_name not in profile_names:
                    profile_names.append(profile_name)
            if not profile_names:
                continue
            # Generic browser first lets yt-dlp choose its default/recent profile.
            candidates.append(browser)
            for profile_name in profile_names:
                if profile_name in {"", "."}:
                    continue
                candidates.append(f"{browser}:{profile_name}")
        return candidates

    def _summarize_browser_cookie_errors(self, errors: Sequence[Tuple[Optional[str], str]]) -> str:
        # Prefer actionable errors over a later missing-browser/profile error.
        preferred = None
        for spec, err in errors:
            low = err.lower()
            if "failed to decrypt with dpapi" in low:
                preferred = (spec, err)
                break
        if preferred is None:
            for spec, err in errors:
                low = err.lower()
                if "sign in to confirm" in low or "not a bot" in low or "confirm you" in low:
                    preferred = (spec, err)
                    break
        if preferred is None:
            preferred = errors[-1]
        lines = [self._strip_ansi(preferred[1])]
        if len(errors) > 1:
            lines.append("\n[auto-cookie 尝试记录]")
            for spec, err in errors[:12]:
                label = spec or "no-browser-cookie"
                one_line = self._strip_ansi(err).replace("\n", " ")
                if len(one_line) > 240:
                    one_line = one_line[:240] + "..."
                lines.append(f"- {label}: {one_line}")
            if len(errors) > 12:
                lines.append(f"- ... 还有 {len(errors) - 12} 条已省略")
        lines.append(
            "\n[解决建议] GUI 里先点『Cookie诊断』，选择显示 youtube_cookie_rows>0 的 profile，"
            "例如 chrome:Profile 1 或 edge:Default；运行前请先关闭正在使用的浏览器窗口，"
            "或手动导出 Netscape 格式 cookies.txt 后填入 Cookie 文件。"
        )
        return "\n".join(lines)

    def _dedupe_candidates(self, candidates: Iterable[Optional[str]]) -> List[Optional[str]]:
        seen: Set[Optional[str]] = set()
        out: List[Optional[str]] = []
        for item in candidates:
            if item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out

    def _discover_browser_cookie_profiles(self) -> List[Tuple[str, int]]:
        """Return [(yt-dlp browser spec, youtube_cookie_count), ...].

        The probe looks only at cookie table metadata in a copied SQLite DB. It
        never decrypts or exports cookie values. Missing/locked/unsupported
        profiles are ignored and yt-dlp's own browser-cookie loader remains the
        source of truth for actual authentication.
        """
        roots = self._candidate_browser_roots()
        found: List[Tuple[str, int]] = []
        for browser, root in roots:
            for profile_name, cookie_db in self._iter_cookie_db_paths(root, browser):
                count = self._count_youtube_cookie_rows(cookie_db)
                if count <= 0:
                    continue
                spec = browser if profile_name in {"", "."} else f"{browser}:{profile_name}"
                found.append((spec, count))
                self.logger.info("Detected %s YouTube cookie rows in %s", count, spec)
        found.sort(key=lambda x: x[1], reverse=True)
        return found

    def _candidate_browser_roots(self) -> List[Tuple[str, Path]]:
        home = Path.home()
        roots: List[Tuple[str, Path]] = []
        if sys.platform.startswith("win"):
            local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
            roaming = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
            roots.extend([
                ("chrome", local / "Google" / "Chrome" / "User Data"),
                ("edge", local / "Microsoft" / "Edge" / "User Data"),
                ("brave", local / "BraveSoftware" / "Brave-Browser" / "User Data"),
                ("vivaldi", local / "Vivaldi" / "User Data"),
                ("opera", roaming / "Opera Software" / "Opera Stable"),
                ("firefox", roaming / "Mozilla" / "Firefox" / "Profiles"),
            ])
        elif sys.platform.startswith("darwin"):
            roots.extend([
                ("safari", home / "Library" / "Safari"),
                ("chrome", home / "Library" / "Application Support" / "Google" / "Chrome"),
                ("edge", home / "Library" / "Application Support" / "Microsoft Edge"),
                ("brave", home / "Library" / "Application Support" / "BraveSoftware" / "Brave-Browser"),
                ("vivaldi", home / "Library" / "Application Support" / "Vivaldi"),
                ("opera", home / "Library" / "Application Support" / "com.operasoftware.Opera"),
                ("firefox", home / "Library" / "Application Support" / "Firefox" / "Profiles"),
            ])
        else:
            roots.extend([
                ("chrome", home / ".config" / "google-chrome"),
                ("chromium", home / ".config" / "chromium"),
                ("brave", home / ".config" / "BraveSoftware" / "Brave-Browser"),
                ("edge", home / ".config" / "microsoft-edge"),
                ("vivaldi", home / ".config" / "vivaldi"),
                ("opera", home / ".config" / "opera"),
                ("firefox", home / ".mozilla" / "firefox"),
            ])
        return [(browser, root) for browser, root in roots if root.exists()]

    def _iter_cookie_db_paths(self, root: Path, browser: str = "") -> Iterable[Tuple[str, Path]]:
        if browser == "firefox":
            # Windows/macOS root is usually .../Firefox/Profiles; Linux root is ~/.mozilla/firefox.
            for child in root.iterdir() if root.exists() else []:
                if not child.is_dir():
                    continue
                p = child / "cookies.sqlite"
                if p.exists():
                    yield child.name, p
            direct = root / "cookies.sqlite"
            if direct.exists():
                yield "", direct
            return
        if browser == "safari":
            # Safari cookie storage is not SQLite-compatible here; only use generic yt-dlp safari if present.
            if root.exists():
                yield "", root
            return
        direct = [root / "Network" / "Cookies", root / "Cookies"]
        for p in direct:
            if p.exists():
                yield "", p
        for child in root.iterdir() if root.exists() else []:
            if not child.is_dir():
                continue
            if child.name != "Default" and not child.name.startswith("Profile "):
                continue
            for p in [child / "Network" / "Cookies", child / "Cookies"]:
                if p.exists():
                    yield child.name, p

    def _count_youtube_cookie_rows(self, cookie_db: Path) -> int:
        tmp_path: Optional[Path] = None
        try:
            with tempfile.NamedTemporaryFile(prefix="ctf_ytdl_cookie_probe_", suffix=".sqlite", delete=False) as tmp:
                tmp_path = Path(tmp.name)
            shutil.copy2(cookie_db, tmp_path)
            conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
            try:
                cur = conn.execute("SELECT COUNT(*) FROM cookies WHERE host_key LIKE ?", ("%youtube.com%",))
                return int(cur.fetchone()[0] or 0)
            finally:
                conn.close()
        except Exception as exc:
            self.logger.debug("Cookie profile probe skipped %s: %s", cookie_db, exc)
            return 0
        finally:
            if tmp_path:
                try:
                    tmp_path.unlink(missing_ok=True)
                except Exception:
                    pass
