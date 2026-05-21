from __future__ import annotations

from .analyzer_probe_ops import AnalyzerProbeOpsMixin
from .analyzer_text_ops import AnalyzerTextOpsMixin


class AnalyzerMetadataMixin(AnalyzerProbeOpsMixin, AnalyzerTextOpsMixin):
    pass
