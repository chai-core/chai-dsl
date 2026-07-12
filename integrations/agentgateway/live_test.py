import asyncio, sys
from fastmcp import Client
AG = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000/mcp"

async def call(tool):
    # isolated session so a blocked call can't corrupt another
    async with Client(AG) as c:
        await c.call_tool(tool, {"table": "t"})

async def main():
    res = []
    try:
        await call("read"); res.append(("read PERMITTED (PDP allow -> agentgateway 200)", True, ""))
    except Exception as e:
        res.append(("read PERMITTED (PDP allow -> agentgateway 200)", False, f"blocked: {type(e).__name__}"))
    try:
        await call("write"); res.append(("write BLOCKED (PDP deny -> agentgateway 403)", False, "NOT blocked!"))
    except Exception as e:
        res.append(("write BLOCKED (PDP deny -> agentgateway 403)", True, f"blocked: {type(e).__name__}"))
    for n, ok, d in res: print(f"  [{'PASS' if ok else 'FAIL'}] {n}  {d}")
    p = sum(1 for _, ok, _ in res if ok); print(f"\n{p}/{len(res)} through agentgateway")
    sys.exit(0 if p == len(res) else 1)
asyncio.run(main())
