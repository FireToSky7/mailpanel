#!/usr/bin/env python3
"""Called by Fail2ban actionban: optionally disable attacked mailbox."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

from app.services.fail2ban_ops import disable_mailboxes_for_banned_ip  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", required=True)
    parser.add_argument("--jail", default="")
    args = parser.parse_args()
    disabled = disable_mailboxes_for_banned_ip(args.ip.strip(), args.jail.strip())
    if disabled:
        print("disabled:" + ",".join(disabled))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
