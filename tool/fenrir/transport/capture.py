"""Timestamped JSON capture logger for L0/L1/L2 interactions."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fenrir.constants import CAPTURES_DIR


class CaptureLogger:
    """Records every probe step and raw hex frame in memory and to disk."""

    def __init__(self, session_name: str = "probe", output_dir: Path | None = None) -> None:
        self.output_dir = output_dir or CAPTURES_DIR
        self.started_at = datetime.now(timezone.utc)
        stamp = self.started_at.strftime("%Y%m%d_%H%M%S")
        self.session_name = session_name
        self.file_path = self.output_dir / f"{stamp}_{session_name}.json"
        self.events: list[dict[str, Any]] = []
        self.metadata: dict[str, Any] = {
            "session_name": session_name,
            "started_at_utc": self.started_at.isoformat(),
        }

    def record(self, kind: str, **payload: Any) -> None:
        self.events.append(
            {
                "seq": len(self.events),
                "ts_utc": datetime.now(timezone.utc).isoformat(),
                "kind": kind,
                **payload,
            }
        )

    def save(self, path: Path | None = None) -> Path:
        target = path or self.file_path
        target.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "metadata": self.metadata,
            "event_count": len(self.events),
            "events": self.events,
        }
        target.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        return target
