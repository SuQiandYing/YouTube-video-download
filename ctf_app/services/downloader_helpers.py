from __future__ import annotations

from .downloader_cookies import DownloaderCookieMixin
from .downloader_errors import DownloaderErrorMixin
from .downloader_options import DownloaderOptionsMixin
from .downloader_sidecars import DownloaderSidecarMixin
from .downloader_summary import DownloaderSummaryMixin


class DownloaderHelperMixin(
    DownloaderSidecarMixin,
    DownloaderErrorMixin,
    DownloaderCookieMixin,
    DownloaderOptionsMixin,
    DownloaderSummaryMixin,
):
    pass
