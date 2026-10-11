"""Phase 1 tests: tool configuration + health foundation only.

No reconnaissance — only YAML loading and version-command checks.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.core.tool_manager import (
    PROJECTDISCOVERY_HTTPX_EXE,
    ToolConfig,
    check_tool,
    load_tools_config,
)


def test_yaml_configuration_loading():
    configs = load_tools_config()
    names = {c.name for c in configs}
    assert names == {
        "subfinder",
        "crtsh",
        "dnsx",
        "httpx",
        "naabu",
        "nmap",
        "whatweb",
        "katana",
        "gowitness",
        "nuclei",
        "ollama",
    }
    for c in configs:
        assert c.name
        assert c.executable is not None
        assert isinstance(c.version_command, list)
        assert c.purpose
    httpx_cfg = next(c for c in configs if c.name == "httpx")
    assert httpx_cfg.executable == PROJECTDISCOVERY_HTTPX_EXE
    assert httpx_cfg.enabled is True
    whatweb = next(c for c in configs if c.name == "whatweb")
    assert whatweb.enabled is False


def test_existing_executable_detection():
    cfg = ToolConfig(
        name="python",
        executable=sys.executable,
        enabled=True,
        version_command=["--version"],
        purpose="test",
    )
    result = check_tool(cfg)
    assert result.status == "ready"
    assert result.available is True
    assert result.version is not None


def test_missing_executable_detection():
    cfg = ToolConfig(
        name="missing-tool",
        executable=r"C:\nonexistent-tracehound-tool-12345.exe",
        enabled=True,
        version_command=["--version"],
        purpose="test",
    )
    result = check_tool(cfg)
    assert result.status == "missing"
    assert result.available is False


def test_disabled_tool_handling():
    cfg = ToolConfig(
        name="whatweb",
        executable="whatweb",
        enabled=False,
        version_command=["--version"],
        purpose="test",
    )
    result = check_tool(cfg)
    assert result.status == "disabled"
    assert result.available is False
    assert result.stdout == ""
    assert result.stderr == ""


def test_projectdiscovery_httpx_detection():
    configs = load_tools_config()
    httpx_cfg = next(c for c in configs if c.name == "httpx")
    assert httpx_cfg.executable == PROJECTDISCOVERY_HTTPX_EXE
    result = check_tool(httpx_cfg)
    # Binary is verified present in this environment.
    assert result.executable == PROJECTDISCOVERY_HTTPX_EXE
    assert result.status == "ready"
    assert result.available is True
    assert result.version is not None
    combined = f"{result.stdout}\n{result.stderr}".lower()
    assert "projectdiscovery" in combined


def test_httpx_bare_path_rejected():
    cfg = ToolConfig(
        name="httpx",
        executable="httpx",
        enabled=True,
        version_command=["-version"],
        purpose="test",
    )
    result = check_tool(cfg)
    assert result.status == "error"
    assert result.available is False


def test_python_httpx_remains_importable():
    import httpx

    assert httpx.__version__
    assert "site-packages" in httpx.__file__.replace("\\", "/")


def test_tool_health_api_response():
    from fastapi.testclient import TestClient

    from backend.main import app

    client = TestClient(app)
    resp = client.get("/api/system/tools")
    assert resp.status_code == 200
    data = resp.json()
    assert "tools" in data
    tools = {t["name"]: t for t in data["tools"]}
    assert set(tools) >= {
        "subfinder",
        "crtsh",
        "dnsx",
        "httpx",
        "naabu",
        "nmap",
        "whatweb",
        "katana",
        "gowitness",
        "nuclei",
        "ollama",
    }
    for entry in data["tools"]:
        assert entry["status"] in ("ready", "missing", "disabled", "error")
        assert "available" in entry
        assert "version" in entry
    assert tools["whatweb"]["status"] in ("disabled", "missing")
    assert tools["httpx"]["executable"] == PROJECTDISCOVERY_HTTPX_EXE
    # Do not leak secrets.
    assert "secret" not in resp.text.lower()
    assert "api_key" not in resp.text.lower()
