import { existsSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

/**
 * Resolves path-like tokens against the caller's working directory.
 *
 * The server runs inside a sandbox workdir, so `node examples/server.mjs` would
 * otherwise be resolved there and fail. Only tokens that look like paths are
 * touched: command names (`node`, `uvx`) and flags are left alone.
 */
export function absolutizeCommand(command: string[], cwd: string = process.cwd()): string[] {
  return command.map((token) => {
    if (!token) return token;
    if (token.startsWith("-")) return token;
    if (isAbsolute(token)) return token;
    if (token.includes("://")) return token;

    const looksLikePath =
      token.includes("/") || token.includes("\\") || /\.(mjs|cjs|js|ts|tsx|py|rb|php|jar)$/i.test(token);
    if (!looksLikePath) return token;

    const candidate = resolve(cwd, token);
    return existsSync(candidate) ? candidate : token;
  });
}
