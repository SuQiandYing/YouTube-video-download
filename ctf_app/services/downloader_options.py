from __future__ import annotations

from .downloader_formatting import DownloaderFormattingMixin
from .downloader_runtime_env import DownloaderRuntimeEnvMixin


class DownloaderOptionsMixin(DownloaderFormattingMixin, DownloaderRuntimeEnvMixin):
    pass
