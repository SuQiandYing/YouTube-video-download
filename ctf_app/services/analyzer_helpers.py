from __future__ import annotations

from .analyzer_media_ops import AnalyzerMediaOpsMixin
from .analyzer_metadata import AnalyzerMetadataMixin
from .analyzer_reporting import AnalyzerReportingMixin


class AnalyzerHelperMixin(AnalyzerMetadataMixin, AnalyzerMediaOpsMixin, AnalyzerReportingMixin):
    pass
