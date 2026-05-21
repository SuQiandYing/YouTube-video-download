from __future__ import annotations

from .contracts import DownloaderFactory, DownloaderService
from .downloader_impl import CTFYouTubeDownloader, YtDlpLogger
from .downloader_cli_support import build_arg_parser, collect_urls, main
from .downloader_helpers import DownloaderHelperMixin
from .models import DownloadTaskResult, NonRetryableDownloadError



def create_downloader_service(*args, **kwargs) -> DownloaderService:
    return CTFYouTubeDownloader(*args, **kwargs)


DOWNLOADER_FACTORY: DownloaderFactory = create_downloader_service

__all__ = [
    "CTFYouTubeDownloader",
    "DOWNLOADER_FACTORY",
    "DownloadTaskResult",
    "NonRetryableDownloadError",
    "YtDlpLogger",
    "build_arg_parser",
    "collect_urls",
    "create_downloader_service",
    "main",
    "probe_target_info",
]



def probe_target_info(config, args, logger, url, *, playlist=False):
    try:
        import yt_dlp
    except ImportError as exc:
        raise RuntimeError("yt-dlp is not installed. Run: python -m pip install -r requirements.txt") from exc
    downloader = CTFYouTubeDownloader(config, args, logger)
    opts = downloader._build_ydl_opts(url)
    opts["format"] = None
    opts.pop("merge_output_format", None)
    opts.pop("postprocessors", None)
    opts["noplaylist"] = not playlist
    opts["skip_download"] = True
    opts["quiet"] = True
    opts["ignoreerrors"] = True if playlist else False
    opts.pop("progress_hooks", None)
    if playlist:
        opts["extract_flat"] = "in_playlist"
    with yt_dlp.YoutubeDL(opts) as ydl:
        info = ydl.extract_info(url, download=False)
    if not isinstance(info, dict):
        raise RuntimeError("yt-dlp probe returned no metadata")
    return info
