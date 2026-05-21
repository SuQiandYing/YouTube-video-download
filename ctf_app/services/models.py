from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DownloadTaskResult:
    url: str
    ok: bool
    attempt_count: int
    downloaded_files: List[str] = field(default_factory=list)
    media_files: List[str] = field(default_factory=list)
    artifact_files: List[str] = field(default_factory=list)
    error: Optional[str] = None
    elapsed_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ArtifactRecord:
    path: str
    kind: str
    note: str = ""


@dataclass
class AnalysisResult:
    input_file: str
    output_dir: str
    hashes: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    command_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    keyword_hits: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    artifacts: List[ArtifactRecord] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["artifacts"] = [asdict(item) for item in self.artifacts]
        return data


class NonRetryableDownloadError(RuntimeError):
    """Raised for local configuration/authentication errors that retries cannot fix."""
