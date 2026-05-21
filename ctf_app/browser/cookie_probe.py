# FOR CTF & SECURITY RESEARCH USE ONLY
"""
Local browser YouTube cookie profile probe.

This diagnostic checks only cookie database metadata: profile path, cookie names,
and host row counts. It never decrypts or prints cookie values.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

SENSITIVE_NAMES = {"SID", "HSID", "SSID", "APISID", "SAPISID", "LOGIN_INFO", "__Secure-1PSID", "__Secure-3PSID"}


def candidate_browser_roots() -> List[Tuple[str, Path]]:
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
    return [(b, r) for b, r in roots if r.exists()]


def iter_cookie_db_paths(root: Path, browser: str = "") -> Iterable[Tuple[str, Path]]:
    if browser == "firefox":
        if not root.exists():
            return
        for child in root.iterdir():
            if not child.is_dir():
                continue
            p = child / "cookies.sqlite"
            if p.exists():
                yield child.name, p
        direct = root / "cookies.sqlite"
        if direct.exists():
            yield "", direct
        return
    for p in [root / "Network" / "Cookies", root / "Cookies"]:
        if p.exists():
            yield "", p
    if not root.exists():
        return
    for child in root.iterdir():
        if not child.is_dir():
            continue
        if child.name != "Default" and not child.name.startswith("Profile "):
            continue
        for p in [child / "Network" / "Cookies", child / "Cookies"]:
            if p.exists():
                yield child.name, p


def read_cookie_summary(cookie_db: Path) -> Dict[str, object]:
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="ctf_ytdl_cookie_probe_", suffix=".sqlite", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        shutil.copy2(cookie_db, tmp_path)
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        try:
            rows = conn.execute(
                "SELECT host_key, name FROM cookies WHERE host_key LIKE ? ORDER BY host_key, name",
                ("%youtube.com%",),
            ).fetchall()
            names = sorted({str(name) for _host, name in rows})
            important = [name for name in names if name in SENSITIVE_NAMES or name.startswith("__Secure-")]
            return {
                "ok": True,
                "youtube_cookie_rows": len(rows),
                "sample_cookie_names": names[:20],
                "important_cookie_names_present": important[:30],
                "error": None,
            }
        finally:
            conn.close()
    except Exception as exc:
        return {"ok": False, "youtube_cookie_rows": 0, "sample_cookie_names": [], "important_cookie_names_present": [], "error": str(exc)}
    finally:
        if tmp_path:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass


def probe() -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    for browser, root in candidate_browser_roots():
        for profile, db in iter_cookie_db_paths(root, browser):
            summary = read_cookie_summary(db)
            spec = browser if profile in {"", "."} else f"{browser}:{profile}"
            results.append({
                "browser_spec": spec,
                "browser": browser,
                "profile": profile or "(root)",
                "cookie_db": str(db),
                **summary,
            })
    results.sort(key=lambda x: int(x.get("youtube_cookie_rows") or 0), reverse=True)
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description="Diagnose local browser profiles that contain YouTube cookie metadata. Values are never printed.")
    ap.add_argument("--json", action="store_true", help="Print JSON only")
    args = ap.parse_args()
    results = probe()
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0 if any(int(r.get("youtube_cookie_rows") or 0) > 0 for r in results) else 2

    print("FOR CTF & SECURITY RESEARCH USE ONLY")
    print("YouTube browser-cookie profile diagnostic")
    print("Cookie values are NOT decrypted or printed.\n")
    if not results:
        print("No supported browser cookie databases were found.")
        print("Try logging in with Firefox and selecting 'firefox', or choose a cookies.txt file.")
        return 2
    for r in results:
        count = int(r.get("youtube_cookie_rows") or 0)
        status = "OK" if count > 0 else "--"
        print(f"[{status}] {r['browser_spec']}: youtube_cookie_rows={count}")
        if r.get("important_cookie_names_present"):
            print("     login-looking cookie names:", ", ".join(r["important_cookie_names_present"]))
        if r.get("error"):
            print("     error:", r["error"])
    best = next((r for r in results if int(r.get("youtube_cookie_rows") or 0) > 0), None)
    if best:
        print("\nSuggested GUI setting: 浏览器Cookie =", best["browser_spec"])
        return 0
    print("\nNo YouTube cookie rows found. Open YouTube in your browser and log in, or select a cookies.txt file.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
