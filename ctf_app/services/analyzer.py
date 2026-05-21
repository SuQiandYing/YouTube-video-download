from __future__ import annotations

from .analyzer_impl import AnalysisResult, ArtifactRecord, ForensicAnalyzer, main


def create_analyzer_service(*args, **kwargs) -> ForensicAnalyzer:
    return ForensicAnalyzer(*args, **kwargs)


__all__ = [
    "AnalysisResult",
    "ArtifactRecord",
    "ForensicAnalyzer",
    "create_analyzer_service",
    "main",
]
