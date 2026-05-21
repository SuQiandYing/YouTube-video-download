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


class DownloaderErrorMixin:
    def _friendly_error(self, error: str) -> str:
        error = self._strip_ansi(error)
        low = error.lower()
        if "failed to decrypt with dpapi" in low:
            return (
                error
                + "\n\n[解决建议] 你选中的 Chrome/Edge Profile 里确实有 YouTube Cookie，但 Windows/Chromium 的 Cookie 加密导致 yt-dlp 无法用 DPAPI 解密。"
                  "这不是 Profile 号错误，继续重试同一个 Profile 没用。请用下面任一方法："
                  "\n1) 在 GUI 右侧 Cookie 文件处选择你自己导出的 Netscape 格式 cookies.txt；"
                  "\n2) 用 Firefox 登录 YouTube，再选择 浏览器Cookie=firefox；"
                  "\n3) 若仍用 Chrome/Edge，请先完全关闭浏览器后再试；仍失败就改用 cookies.txt。"
                  "\nCookie 等同登录凭证，只保存在本机使用，不要发给别人；不要绕过未授权访问或 DRM。"
            )
        if "n challenge solving failed" in low or "only images are available" in low:
            return (
                error
                + "\n\n[解决建议] Cookie 已经生效，但 YouTube 的 n 参数/签名挑战没有被解开，"
                  "所以 yt-dlp 只能看到图片/缩略图格式，视频和音频格式被隐藏，最终表现为『Requested format is not available』。"
                  "请运行 `python start.py --install-runtime` 安装/修复 Deno + yt-dlp-ejs，或手动执行："
                  "python -m pip install -U yt-dlp yt-dlp-ejs，然后安装 Deno 并确保 deno 在 PATH 中。"
            )
        if "requested format is not available" in low:
            return (
                error
                + "\n\n[解决建议] 当前不是分辨率问题，通常是上游日志里已有『n challenge solving failed』，"
                  "导致视频/音频格式没有被解析出来。请先运行 `python start.py --install-runtime` 修复 YouTube EJS/JS runtime，"
                  "再用 Cookie 文件重试。"
            )
        marker = "Sign in to confirm"
        if marker in error or "not a bot" in error:
            return (
                error
                + "\n\n[解决建议] YouTube 要求登录/人机验证。本版会在 auto 模式自动扫描 Edge/Chrome/Brave 的常见 Profile，"
                  "GUI 下拉框现在支持 Profile 1-30，并会把 Cookie诊断发现的 Profile 自动加入。"
                  "如果仍失败，请选择 Cookie诊断建议的值，例如 chrome:Profile 10；"
                  "若遇到 DPAPI 解密失败，请改用本机导出的 Netscape 格式 cookies.txt 或 Firefox。"
                  "Cookie 是登录凭证，不要发给别人；不要绕过未授权访问或 DRM。"
            )
        return error

    @staticmethod
    def _strip_ansi(text: str) -> str:
        text = re.sub(r"\x1b\[[0-9;]*m", "", text)
        text = re.sub(r"\[0;3[0-9]m", "", text)
        text = text.replace("[0m", "")
        return text

    @staticmethod
    def _is_non_retryable_error(error: str) -> bool:
        low = error.lower()
        return any(x in low for x in [
            "failed to decrypt with dpapi",
            "sign in to confirm",
            "not a bot",
            "could not find",
            "permission denied",
        ])

