/**
 * Safety rails for collection targets.
 *
 * The collector is passive, but "passive" is not "authorised". These checks
 * exist so the tool cannot be pointed at arbitrary third-party infrastructure
 * by accident, and so the consent requirement is impossible to skip silently.
 */

export class UnsafeTargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsafeTargetError";
  }
}

function isLoopback(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname === "[::1]" ||
    hostname.endsWith(".localhost")
  );
}

export function assertScannableTarget(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new UnsafeTargetError(`Not a valid absolute URL: ${raw}`);
  }

  if (url.username || url.password) {
    throw new UnsafeTargetError("Credentials must not be embedded in the target URL.");
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback(url.hostname))) {
    throw new UnsafeTargetError(
      `Refusing ${url.protocol} for ${url.hostname}. Use https, or http only against loopback during development.`,
    );
  }
  return url;
}

export const CONSENT_NOTICE = `
mcp-threat-observatory performs a passive handshake, but it still contacts the
target. That requires authorisation from the operator of the server.

  Allowed:      a server you operate, or that you have written permission to test
  Not allowed:  arbitrary servers you found in a registry, "just to see"

Pass --authorized (or set MCPOBS_AUTHORIZED=1) to confirm you have permission.
`.trim();

export function isAuthorized(flag: boolean | undefined): boolean {
  return flag === true || process.env.MCPOBS_AUTHORIZED === "1";
}
