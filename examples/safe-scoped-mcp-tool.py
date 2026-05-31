# Safe example: scoped MCP tool with fixed allowlist and no shell.
# Expected result: findings: [].

from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("ops")
ALLOWED = {
    "uptime": ["uptime"],
    "disk": ["df", "-h"],
}


@mcp.tool()
def run_known(name: str) -> str:
    argv = ALLOWED.get(name)
    if argv is None:
        raise ValueError("operation denied")
    return subprocess.run(argv, capture_output=True, text=True).stdout
