from __future__ import annotations

from .downloader_browser_profiles import DownloaderBrowserProfilesMixin
from .downloader_download import DownloaderDownloadMixin


class DownloaderCookieMixin(DownloaderDownloadMixin, DownloaderBrowserProfilesMixin):
    pass
