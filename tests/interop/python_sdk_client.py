#!/usr/bin/env python3
"""Client path B: official Python MCP SDK client driving a real server through mcp-visor.

Reproduce (external person):
  # 1. start visor proxying the real filesystem server
  mcp-visor serve -server npx -server-arg -y \
    -server-arg @modelcontextprotocol/server-filesystem@2026.7.10 \
    -server-arg /tmp/interop-sandbox -server-name filesystem \
    -policy examples/policies/interop/filesystem-sandbox.yaml \
    -audit-log /tmp/visor-audit.jsonl &
  # 2. run this client; pass the visor command and its arguments
  uvx --with mcp==1.26.0 python3 tests/interop/python_sdk_client.py \
    mcp-visor serve \
    -server npx -server-arg -y \
    -server-arg @modelcontextprotocol/server-filesystem@2026.7.10 \
    -server-arg /tmp/interop-sandbox \
    -server-name filesystem \
    -policy examples/policies/interop/filesystem-sandbox.yaml
"""
import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    params = StdioServerParameters(
        command=sys.argv[1] if len(sys.argv) > 1 else "mcp-visor",
        args=sys.argv[2:],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            print("SERVER_INFO:", json.dumps({
                "name": init.serverInfo.name,
                "version": init.serverInfo.version,
                "protocolVersion": init.protocolVersion,
            }))
            tools = await session.list_tools()
            names = sorted(t.name for t in tools.tools)
            print("TOOLS:", json.dumps(names))
            res = await session.call_tool(
                "read_file",
                {"path": "/tmp/interop-sandbox/docs/readme.txt"},
            )
            text = "".join(
                c.text for c in res.content if getattr(c, "type", "") == "text"
            )
            print("READ_RESULT:", json.dumps(text))


if __name__ == "__main__":
    asyncio.run(main())
