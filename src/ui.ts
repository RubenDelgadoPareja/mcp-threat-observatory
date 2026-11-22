import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { buildSnapshot } from "./analyze.ts";
import { probeServer } from "./collect/probe.ts";
import { BASE_CSS, renderSnapshotHtml } from "./output/html.ts";
import { writeSnapshot } from "./output/snapshot.ts";
import { assertScannableTarget, UnsafeTargetError } from "./safety.ts";

export interface UiOptions {
  port?: number;
  outDir?: string;
  rateLimitRps?: number;
  timeoutMs?: number;
}

export interface UiServer {
  url: string;
  token: string;
  close: () => Promise<void>;
}

const UI_CSS = `
  .console { display:grid; grid-template-columns:minmax(0,1.55fr) minmax(0,.85fr); gap:1rem; margin-top:1.5rem; }
  @media (max-width:860px) { .console { grid-template-columns:1fr; } }
  .panel {
    border:1px solid var(--line); border-radius:var(--radius);
    background:linear-gradient(180deg,var(--panel-2),var(--panel)); padding:1.1rem 1.15rem;
  }
  .mono-label {
    display:block; font-family:var(--mono); font-size:.66rem; letter-spacing:.14em;
    text-transform:uppercase; color:var(--faint); margin:0 0 .45rem;
  }
  .input-row {
    display:flex; align-items:center; gap:.6rem; padding:.1rem .75rem;
    border:1px solid var(--line-2); border-radius:.4rem; background:var(--bg-2);
  }
  .input-row:focus-within {
    border-color:var(--accent);
    box-shadow:0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent);
  }
  .prompt { font-family:var(--mono); color:var(--accent); }
  input[type=url] {
    flex:1; min-width:0; border:0; outline:none; background:transparent; color:var(--fg);
    font:inherit; font-family:var(--mono); font-size:.9rem; padding:.65rem 0;
  }
  .hint { margin:.5rem 0 1rem; color:var(--faint); font-size:.82rem; }
  .check {
    display:flex; gap:.6rem; align-items:flex-start; margin:0 0 1.15rem;
    color:var(--muted); font-size:.86rem; line-height:1.5;
  }
  .check input { margin-top:.22rem; accent-color:var(--accent); }
  button {
    font:inherit; font-weight:650; font-size:.9rem; letter-spacing:.02em;
    padding:.62rem 1.05rem; border-radius:.4rem; cursor:pointer;
    border:1px solid var(--accent); background:var(--accent); color:var(--accent-fg);
  }
  button:hover { filter:brightness(1.08); }
  button:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
  .facts { font-size:.85rem; color:var(--muted); }
  .facts ul { margin:.2rem 0 0 1rem; padding:0; }
  .facts li { margin:.35rem 0; }
  .facts code { font-size:.8rem; }
  .back { display:inline-block; margin-top:1.25rem; font-family:var(--mono); font-size:.82rem; color:var(--accent); }
`;

function shell(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${escape(title)}</title>
<style>${BASE_CSS}${UI_CSS}</style>
</head>
<body>
<main>
<div class="masthead">
  <span class="brand"><span class="status-dot"></span>mcp threat observatory</span>
  <span class="right"><span>local collector</span><span class="tlp">127.0.0.1</span></span>
</div>
${body}
</main>
</body>
</html>
`;
}

function formPage(token: string): string {
  return shell(
    "mcp-threat-observatory",
    `<div class="title-block">
  <h1>Passive observation<span class="accent">console</span></h1>
  <p class="lede">Point it at an MCP endpoint. It performs what an ordinary client does before authenticating, and nothing more.</p>
</div>
<div class="console">
  <div class="panel">
    <form method="POST" action="/scan?token=${encodeURIComponent(token)}">
      <label class="mono-label" for="url">target endpoint</label>
      <div class="input-row">
        <span class="prompt">$</span>
        <input id="url" name="url" type="url" required placeholder="https://example.com/mcp" autofocus spellcheck="false">
      </div>
      <p class="hint">Paste the endpoint itself (usually ending in <code>/mcp</code>). Do not open it in a tab: an MCP server answers protocol requests, not web pages.</p>
      <label class="check">
        <input type="checkbox" name="attest" value="yes" required>
        <span>I operate this server, or I have written permission to observe it.</span>
      </label>
      <button type="submit">Run passive scan</button>
    </form>
  </div>
  <aside class="panel facts">
    <p class="mono-label">what runs</p>
    <ul>
      <li><code>initialize</code>, <code>tools/list</code>, <code>resources/list</code>, <code>prompts/list</code></li>
      <li>No tool is invoked. No payload is sent.</li>
      <li>At most one request per second.</li>
      <li>Runs on this machine, not on a remote service.</li>
    </ul>
  </aside>
</div>`,
  );
}

function errorPage(status: number, message: string, token?: string): string {
  const back = token
    ? `<a class="back" href="/?token=${encodeURIComponent(token)}">← back to the console</a>`
    : "";
  return shell(
    `${status}`,
    `<div class="title-block">
  <h1>${status}<span class="accent">refused</span></h1>
  <p class="lede">${escape(message)}</p>
</div>
${back}`,
  );
}

function escape(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function readForm(req: IncomingMessage, limit = 8 * 1024): Promise<URLSearchParams> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) throw new Error("request body too large");
    chunks.push(chunk as Buffer);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

function tokenFrom(req: IncomingMessage): string | null {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  return url.searchParams.get("token");
}

/**
 * A local, passive-only UI.
 *
 * Three deliberate constraints:
 *   - it binds to 127.0.0.1 and never to a public interface;
 *   - every request needs a token generated at startup, so a random web page
 *     cannot drive it;
 *   - it exposes no command field. Executing arbitrary code from a browser
 *     request is not a feature, it is remote code execution.
 */
export async function startUiServer(options: UiOptions = {}): Promise<UiServer> {
  const outDir = options.outDir ?? "snapshots";
  const token = randomBytes(16).toString("hex");
  let busy = false;

  const server = createServer(async (req, res) => {
    const requestUrl = new URL(req.url ?? "/", "http://127.0.0.1");

    if (requestUrl.pathname === "/health") {
      res.writeHead(200, { "content-type": "text/plain" }).end("ok");
      return;
    }

    if (tokenFrom(req) !== token) {
      res.writeHead(403, { "content-type": "text/html; charset=utf-8" }).end(
        errorPage(403, "Invalid or missing token. Use the full URL printed by the CLI."),
      );
      return;
    }

    const origin = req.headers.origin;
    if (origin && !origin.startsWith("http://127.0.0.1:") && !origin.startsWith("http://localhost:")) {
      res.writeHead(403, { "content-type": "text/html; charset=utf-8" }).end(errorPage(403, "Cross-origin request refused."));
      return;
    }

    if (req.method === "GET" && requestUrl.pathname === "/") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(formPage(token));
      return;
    }

    if (req.method !== "POST" || requestUrl.pathname !== "/scan") {
      res.writeHead(404, { "content-type": "text/html; charset=utf-8" }).end(errorPage(404, "Not found.", token));
      return;
    }

    if (busy) {
      res.writeHead(429, { "content-type": "text/html; charset=utf-8" }).end(
        errorPage(429, "A scan is already running. Wait for it to finish.", token),
      );
      return;
    }

    let form: URLSearchParams;
    try {
      form = await readForm(req);
    } catch {
      res.writeHead(400, { "content-type": "text/html; charset=utf-8" }).end(errorPage(400, "Malformed request.", token));
      return;
    }

    if (form.get("attest") !== "yes") {
      res.writeHead(400, { "content-type": "text/html; charset=utf-8" }).end(
        errorPage(400, "You must attest that you are authorised to observe this server.", token),
      );
      return;
    }

    let target: URL;
    try {
      target = assertScannableTarget(form.get("url") ?? "");
    } catch (error) {
      const message = error instanceof UnsafeTargetError ? error.message : "Invalid URL.";
      res.writeHead(400, { "content-type": "text/html; charset=utf-8" }).end(errorPage(400, message, token));
      return;
    }

    const address = server.address() as AddressInfo | null;
    if (address && target.port === String(address.port) && target.hostname === "127.0.0.1") {
      res.writeHead(400, { "content-type": "text/html; charset=utf-8" }).end(
        errorPage(400, "That is this UI, not an MCP endpoint. Paste the server's /mcp URL instead.", token),
      );
      return;
    }

    busy = true;
    try {
      const probe = await probeServer(target.toString(), {
        rateLimitRps: options.rateLimitRps ?? 1,
        timeoutMs: options.timeoutMs ?? 15_000,
      });
      probe.limitations = [
        ...probe.limitations,
        "Authorisation was attested by the operator in the local UI; the collector cannot verify it.",
      ];
      const snapshot = buildSnapshot(probe);
      await writeSnapshot(outDir, snapshot);
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(renderSnapshotHtml(snapshot));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      res.writeHead(500, { "content-type": "text/html; charset=utf-8" }).end(errorPage(500, message, token));
    } finally {
      busy = false;
    }
  });

  await new Promise<void>((resolve) => server.listen(options.port ?? 4040, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${port}/?token=${token}`,
    token,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections?.();
      }),
  };
}
