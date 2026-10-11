"""TraceHoundAI tool health CLI — Phase 1.

Usage (from project root):
    python scripts/health_check.py
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.core.tool_manager import check_all_tools


def main() -> int:
    results = check_all_tools()
    widths = {
        "tool": max([4] + [len(r.name) for r in results]),
        "status": max([6] + [len(r.status) for r in results]),
        "version": max([7] + [len(str(r.version or "-")) for r in results]),
        "executable": max([10] + [len(r.executable or "-") for r in results]),
    }
    header = (
        f"{'Tool':<{widths['tool']}}  "
        f"{'Status':<{widths['status']}}  "
        f"{'Version':<{widths['version']}}  "
        f"{'Executable':<{widths['executable']}}"
    )
    print(header)
    print("-" * len(header))
    for r in results:
        print(
            f"{r.name:<{widths['tool']}}  "
            f"{r.status:<{widths['status']}}  "
            f"{str(r.version or '-'): <{widths['version']}}  "
            f"{(r.executable or '-'): <{widths['executable']}}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
