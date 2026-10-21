"""Minimal stdio MCP server whose only tool reports its process id and user."""

import json
import os
import sys

for line in sys.stdin:
    message = json.loads(line)
    method, msg_id = message.get("method"), message.get("id")
    if msg_id is None:
        continue
    if method == "initialize":
        result = {
            "protocolVersion": message["params"]["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "pid-server", "version": "0.0.0"},
        }
    elif method == "tools/list":
        result = {"tools": [{"name": "whoami", "inputSchema": {"type": "object"}}]}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": f"{os.getpid()} {os.environ['AIRLOCK_USER']}"}]}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}), flush=True)
