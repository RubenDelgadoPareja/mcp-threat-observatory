import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { buildSnapshot } from "./analyze.ts";
import { probeServer } from "./collect/probe.ts";
import { renderSnapshotHtml } from "./output/html.ts";
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

const FORM_CSS = `
  :root { color-scheme: light dark; --fg:#1c1d21; --muted:#5d6068; --bg:#fbfbfc; --card:#fff;
          --line:#e4e5ea; --accent:#2f5fd0; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e8e9ee; --muted:#a2a6b3; --bg:#16171b; --card:#1d1f25; --line:#2c2f38; --accent:#8ba8ff; }
  }
  * { box-sizing:border-box; }
  body { margin:0; padding:3rem 1.25rem; background:var(--bg); color:var(--fg);
         font:16px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  main { max-width:36rem; margin:0 auto; }
  h1 { font-size:1.4rem; margin:0 0 .4rem; }
  p.sub { color:var(--muted); margin:0 0 1.75rem; font-size:.95rem; }
  form { background:var(--card); border:1px solid var(--line); border-radius:.7rem; padding:1.25rem; }
  label { display:block; font-size:.85rem; font-weight:600; margin:0 0 .35rem; }
  input[type=url] { width:100%; padding:.6rem .7rem; font:inherit; color:inherit; background:transparent;
                     border:1px solid var(--line); border-radius:.45rem; }
  .check { display:flex; gap:.55rem; align-items:flex-start; margin:1rem 0 1.25rem; font-size:.88rem;
           color:var(--muted); font-weight:400; }
  .check input { margin-top:.25rem; }
  button { font:inherit; font-weight:600; padding:.6rem 1rem; border-radius:.45rem; border:1px solid var(--accent);
           background:var(--accent); color:#fff; cursor:pointer; }
  button:disabled { opacity:.6; cursor:progress; }
  .note { margin-top:1.5rem; color:var(--muted); font-size:.85rem; }
  code { font-family:ui-monospace, Menlo, monospace; background:color-mix(in srgb, var(--fg) 8%, transparent);
         padding:.1rem .3rem; border-radius:.25rem; }
`;

function formPage(token: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mcp-threat-observatory</title>
<style>${FORM_CSS}</style>
</head>
<body>
<main>
  <h1>Passive MCP observation</h1>
  <p class="sub">What an ordinary MCP client sees before authenticating. No tool is invoked.</p>
  <form method="POST" action="/scan?token=${encodeURIComponent(token)}">
    <label for="url">MCP endpoint</label>
    <input id="url" name="url" type="url" required placeholder="https://example.com/mcp" autofocus>
    <label class="check">
      <input type="checkbox" name="attest" value="yes" required>
      <span>I operate this server, or I have written permission to observe it.</span>
    </label>
    <button type="submit">Scan</button>
  </form>
  <p class="note">
    The scan runs on this machine, not on a remote service. It sends an unauthenticated
    <code>initialize</code>, <code>tools/list</code>, <code>resources/list</code> and
    <code>prompts/list</code>, at most one request per second. It never calls a tool.
  </p>
</main>
</body>
</html>
`;
}

function errorPage(status: number, message: string, token?: string): string {
  const back = token ? `<p><a href="/?token=${encodeURIComponent(token)}">Back</a></p>` : "";
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${status}</title>
<style>${FORM_CSS}</style></head>
<body><main><h1>${status}</h1><p class="sub">${escape(message)}</p>${back}</main></body></html>
`;
}

function escape(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
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
      res.writeHead(403, { "content-type": "text/html; charset=utf-8" }).end(errorPage(403, "Invalid or missing token."));
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
      res.writeHead(429, { "content-type": "text/html; charset=utf-8" }).end(errorPage(429, "A scan is already running.", token));
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
