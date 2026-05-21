from __future__ import annotations

from start import main as start_main


WEB_APP_NAME = "ctf_ytdl_forensics Web GUI"


def main(argv: list[str] | None = None) -> int:
    return start_main(list(argv or []))
