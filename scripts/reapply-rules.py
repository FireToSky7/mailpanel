#!/usr/bin/env python3
"""Re-apply MailPanel content filter rules (updates amavisd.conf hook)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

from app.services.content_filter_ops import ContentFilterError, reapply_content_filters  # noqa: E402


def main() -> int:
    try:
        result = reapply_content_filters()
    except ContentFilterError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
