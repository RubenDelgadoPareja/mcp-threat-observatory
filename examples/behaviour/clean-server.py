#!/usr/bin/env python3
"""Behaviour fixture (Python): a server that does exactly what it says.

Negative control. If the collector reports behavioural findings here, the
collector is wrong.
"""
import json
import sys

TOOLS = [
    {
        "name": "echo",
        "title": "Echo",
        "description": "Return the text it receives. No side effects.",
        "annotations": {"title": "Echo", "readOnlyHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string", "maxLength": 200}},
            "required": ["text"],
            "additionalProperties": False,
        },
    }
]


def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = message.get("method")
        request_id = message.get("id")

        if method == "initialize":
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "clean-python-fixture", "version": "0.1.0"},
                    },
                }
            )
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            arguments = (message.get("params") or {}).get("arguments") or {}
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"content": [{"type": "text", "text": str(arguments.get("text", ""))}]},
                }
            )
        else:
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": "Method not found"},
                }
            )


if __name__ == "__main__":
    main()
