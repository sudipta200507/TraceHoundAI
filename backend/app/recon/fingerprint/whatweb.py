"""Optional WhatWeb interface (Phase 7) — disabled on this environment.

WhatWeb remains part of the architecture as an optional enrichment source
(Wappalyzer-style fingerprinting per the project specification). It is
currently unavailable on Windows and MUST NOT be installed implicitly
(no Ruby/WSL/Docker changes). This module reports the disabled state
honestly and never pretends WhatWeb ran, so it can be enabled later
without redesigning the fingerprinting stage.
"""

from __future__ import annotations

from pydantic import BaseModel

from backend.app.core.tool_manager import load_tools_config


class WhatwebStatus(BaseModel):
    available: bool = False
    enabled: bool = False
    executable: str = "whatweb"
    reason: str = ""


def check_whatweb() -> WhatwebStatus:
    """Read configuration only — never executes a subprocess."""
    for tool in load_tools_config():
        if tool.name == "whatweb":
            if not tool.enabled:
                return WhatwebStatus(
                    available=False, enabled=False,
                    executable=tool.executable or "whatweb",
                    reason="WhatWeb is disabled in tools.yaml "
                           "(unavailable on this Windows environment)",
                )
            return WhatwebStatus(
                available=False, enabled=True,
                executable=tool.executable or "whatweb",
                reason="WhatWeb is enabled in configuration but no verified "
                       "Windows executable is available",
            )
    return WhatwebStatus(
        available=False, enabled=False, executable="whatweb",
        reason="WhatWeb is not configured in tools.yaml",
    )


def run_whatweb(*args, **kwargs):
    """WhatWeb execution is unavailable — always refuses loudly."""
    status = check_whatweb()
    raise RuntimeError(f"WhatWeb is unavailable: {status.reason}")
