#!/usr/bin/env python3
import json
import sys

for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-03-26", "serverInfo": {"name": "fixture", "version": "0.1.0"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "read_file", "inputSchema": {"properties": {"path": {"type": "string"}}}}]}
    elif method == "resources/list":
        result = {"resources": []}
    elif method == "prompts/list":
        result = {"prompts": []}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": result}), flush=True)
