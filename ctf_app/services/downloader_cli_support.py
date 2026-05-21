from __future__ import annotations

import argparse
from typing import List, Optional, Sequence, Set

from ..core.utils import load_config, read_targets_file, setup_logging


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ctf_ytdl_forensics")
    parser.add_argument("url", nargs="?")
    parser.add_argument("--targets")
    parser.add_argument("--playlist", action="store_true")
    parser.add_argument("--quality")
    parser.add_argument("--audio-only", action="store_true")
    parser.add_argument("--audio-format")
    parser.add_argument("--merge-output-format")
    parser.add_argument("--section")
    parser.add_argument("--sub-langs")
    parser.add_argument("--cookies")
    parser.add_argument("--cookies-from-browser")
    parser.add_argument("--proxy")
    parser.add_argument("--no-proxy", action="store_true")
    parser.add_argument("--limit-rate")
    parser.add_argument("--concurrent", type=int)
    parser.add_argument("--concurrent-fragments", type=int)
    parser.add_argument("--retry", type=int)
    parser.add_argument("--timeout", type=int)
    parser.add_argument("--expected-hashes")
    parser.add_argument("--output-dir")
    parser.add_argument("--results-dir")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--no-analysis", action="store_true")
    parser.add_argument("--log-level", choices=["DEBUG","INFO","WARNING","ERROR"])
    parser.add_argument("--check-robots", action="store_true")
    return parser


def collect_urls(args: argparse.Namespace) -> List[str]:
    urls: List[str] = []
    if args.url:
        urls.append(args.url.strip())
    if args.targets:
        urls.extend(read_targets_file(args.targets))
    seen: Set[str] = set()
    out: List[str] = []
    for url in urls:
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    from .downloader import CTFYouTubeDownloader
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    config = load_config(args.config)
    if args.log_level:
        config.setdefault("logging", {})["level"] = args.log_level
    logger, _ = setup_logging(config.get("logging", {}).get("level", "INFO"))
    try:
        urls = collect_urls(args)
        summary = CTFYouTubeDownloader(config, args, logger).run(urls)
        return 2 if summary.get("failed") else 0
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return 130
    except Exception as exc:
        logger.exception("Fatal error: %s", exc)
        return 1
