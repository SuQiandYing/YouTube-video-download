from __future__ import annotations

from argparse import Namespace
from typing import Any, Mapping, Optional, Protocol, Sequence
import logging


class DownloaderService(Protocol):
    def run(self, urls: Sequence[str]) -> Mapping[str, Any]:
        ...


class DownloaderFactory(Protocol):
    def __call__(self, config: Mapping[str, Any], args: Namespace, logger: logging.Logger) -> DownloaderService:
        ...


class AnalyzerService(Protocol):
    def analyze_many(self, files: Sequence[Any], subtitle_roots: Optional[Sequence[Any]] = None) -> list[Any]:
        ...
