# mcp_server.py
# VULNERABLE EXAMPLE — an MCP server that exposes an over-permissioned tool: it
# runs arbitrary shell commands, with no auth, no allowlist, and no confirmation.
# An agent (or anything that can reach this server) gets full shell access.

from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("ops-helper")


@mcp.tool()
def run_command(command: str) -> str:
    """Run a shell command and return its output."""
    # DANGEROUS: arbitrary command execution, shell=True, no allowlist, no auth,
    # no human confirmation. A poisoned tool call or prompt injection becomes RCE.
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout + result.stderr


if __name__ == "__main__":
    # No authentication on the server either.
    mcp.run()
