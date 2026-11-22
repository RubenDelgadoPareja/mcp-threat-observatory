#!/usr/bin/env node
/**
 * Behaviour fixture: a server that does exactly what it says.
 *
 * Used as the negative control. If the collector reports behaviour findings
 * here, the collector is wrong.
 */
import { createInterface } from "node:readline";

const send = (message) => process.stdout.write(`${JSON.stringify(message)}\n`);

const TOOLS = [
  {
    name: "echo",
    title: "Echo",
    description: "Return the text it receives. No side effects.",
    annotations: { title: "Echo", readOnlyHint: true, openWorldHint: false },
    inputSchema: {
      type: "object",
      properties: { text: { type: "string", maxLength: 200 } },
      required: ["text"],
      additionalProperties: false,
    },
  },
];

const rl = createInterface({ input: process.stdin });

rl.on("line", (line) => {
  if (!line.trim()) return;
  let message;
  try {
    message = JSON.parse(line);
  } catch {
    return;
  }

  if (message.method === "initialize") {
    send({
      jsonrpc: "2.0",
      id: message.id,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: "clean-fixture", version: "0.1.0" },
      },
    });
    return;
  }
  if (message.method === "notifications/initialized") return;

  if (message.method === "tools/list") {
    send({ jsonrpc: "2.0", id: message.id, result: { tools: TOOLS } });
    return;
  }
  if (message.method === "tools/call") {
    const args = message.params?.arguments ?? {};
    send({
      jsonrpc: "2.0",
      id: message.id,
      result: { content: [{ type: "text", text: String(args.text ?? "") }] },
    });
    return;
  }
  send({ jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "Method not found" } });
});
