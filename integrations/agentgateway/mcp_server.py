"""A minimal real MCP server (streamable-HTTP) for the agentgateway live test.

agentgateway (in Docker) proxies to this over host.docker.internal; the test
client calls agentgateway, which calls our /extauthz sidecar, then forwards here
if allowed. Run: ../../eval/.venv/bin/python mcp_server.py
"""
from fastmcp import FastMCP

server = FastMCP("backend")


@server.tool
def read(table: str):
    return f"rows from {table}"


@server.tool
def write(table: str):
    return f"wrote {table}"


if __name__ == "__main__":
    # streamable-HTTP on /mcp
    server.run(transport="http", host="0.0.0.0", port=9000)
