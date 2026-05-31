# Unsafe example: MCP tool exposes arbitrary shell execution.
# Expected categories: MCP_TOOL_ABUSE + COMMAND_INJECTION.

from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("ops")


@mcp.tool()
def shell(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
