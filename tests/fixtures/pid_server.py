"""Minimal stdio MCP server for airlock tests.

Tools:
- whoami: reports its process id and AIRLOCK_USER.
- ask: sends roots/list to the client and returns the client's answer.
- exit: exits without answering.
"""

import json
import os
import sys


def send(message):
    print(json.dumps({"jsonrpc": "2.0", **message}), flush=True)


while line := sys.stdin.readline():
    message = json.loads(line)
    method, msg_id = message.get("method"), message.get("id")
    if method is None or msg_id is None:
        continue
    if method == "initialize":
        result = {
            "protocolVersion": message["params"]["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "pid-server", "version": "0.0.0"},
        }
    elif method == "tools/list":
        names = ["whoami", "ask", "exit"]
        result = {"tools": [{"name": n, "inputSchema": {"type": "object"}} for n in names]}
    elif method == "tools/call":
        tool = message["params"]["name"]
        if tool == "exit":
            sys.exit(0)
        if tool == "ask":
            send({"id": "srv-1", "method": "roots/list"})
            text = json.dumps(json.loads(sys.stdin.readline())["result"])
        else:
            text = f"{os.getpid()} {os.environ['AIRLOCK_USER']}"
        result = {"content": [{"type": "text", "text": text}]}
    else:
        result = {}
    send({"id": msg_id, "result": result})
