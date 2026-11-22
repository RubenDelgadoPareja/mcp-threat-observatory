import type { Check } from "./types.ts";
import { classifyCapabilities } from "./capabilities.ts";

const AUTH_LIMITATION =
  "Only the unauthenticated surface was observed. Behaviour behind the login boundary is unknown.";

export const authChecks: Check[] = [
  {
    id: "AUTH-001",
    title: "MCP endpoint completes a handshake with no credential",
    owasp: ["MCP07"],
    taxonomy: ["authentication"],
    rationale:
      "A server that answers initialize and lists tools without a credential is reachable by anyone who can route to it. Whether that is a defect depends on what the tools can do, so severity is derived from capability, not from the status code alone.",
    run(probe) {
      if (probe.auth.requiresAuth !== false) return [];
      const tools = probe.tools ?? [];
      const capabilities = classifyCapabilities(probe.tools);
      const highImpact = capabilities.highImpact;
      const severity = highImpact.length > 0 ? "high" : "low";

      return [
        {
          severity,
          confidence: "high",
          assertion: "observed",
          observation:
            `An unauthenticated initialize succeeded (HTTP ${probe.auth.statusOnUnauthenticatedInitialize}) ` +
            `and ${tools.length} tool${tools.length === 1 ? "" : "s"} were enumerated.`,
          inference:
            highImpact.length > 0
              ? `Tools with high-impact capability are reachable without a credential: ${highImpact
                  .slice(0, 8)
                  .join(", ")}${highImpact.length > 8 ? "…" : ""}.`
              : "The exposed tool set appears read-mostly. Public read-only servers are a legitimate design.",
          recommendation:
            "If this endpoint is not intentionally public, require OAuth 2.1 per the MCP authorization specification and return 401 with a WWW-Authenticate challenge on unauthenticated requests.",
          limitations: [AUTH_LIMITATION, "Intent is not observable: a public endpoint may be a deliberate choice."],
          evidence: [
            { kind: "http", locator: `POST ${probe.target} → ${probe.auth.statusOnUnauthenticatedInitialize}` },
            { kind: "mcp", locator: "initialize → result", excerpt: probe.handshake.serverInfo?.name },
          ],
          discriminator: severity === "high" ? "high-impact" : "read-mostly",
        },
      ];
    },
  },

  {
    id: "AUTH-002",
    title: "Unauthenticated request returns 403 instead of 401",
    owasp: ["MCP07"],
    taxonomy: ["interoperability", "authentication"],
    rationale:
      "MCP clients discover the authorization server from the WWW-Authenticate challenge on a 401. A 403 carries no such challenge, so compliant clients cannot start the OAuth flow and the user sees a generic connection failure.",
    run(probe) {
      if (probe.auth.statusOnUnauthenticatedInitialize !== 403) return [];
      return [
        {
          severity: "medium",
          confidence: "high",
          assertion: "observed",
          observation: "The unauthenticated initialize request was answered with HTTP 403 Forbidden.",
          inference:
            "MCP authorization discovery is driven by 401 + WWW-Authenticate. A 403 typically prevents clients from discovering how to authenticate, producing failures that look like network errors.",
          recommendation:
            "Return 401 Unauthorized with a WWW-Authenticate: Bearer resource_metadata=\"…\" challenge. Reserve 403 for authenticated requests with insufficient scope.",
          limitations: [
            "Some clients fall back to well-known discovery, so this is not always user-visible.",
            "A 403 may also come from an edge WAF in front of the MCP server, not from the server itself.",
          ],
          evidence: [
            { kind: "http", locator: `POST ${probe.target} → 403`, excerpt: probe.auth.wwwAuthenticate ?? undefined },
          ],
        },
      ];
    },
  },

  {
    id: "AUTH-003",
    title: "Protected Resource Metadata (RFC 9728) is not discoverable",
    owasp: ["MCP07"],
    taxonomy: ["authentication", "interoperability"],
    rationale:
      "The login flow starts with the client fetching the protected resource metadata document. If it is absent, the client has no way to learn which authorization server to use.",
    run(probe) {
      if (probe.auth.requiresAuth !== true) return [];
      const prm = probe.auth.protectedResourceMetadata;
      if (!prm || prm.found) return [];
      return [
        {
          severity: "medium",
          confidence: "high",
          assertion: "observed",
          observation: `The endpoint requires authentication, but no valid protected resource metadata document was found (last status: ${prm.status ?? "no response"}).`,
          inference:
            "Clients that follow the specification cannot auto-discover the authorization server. Users will need manual configuration or will simply fail to connect.",
          recommendation:
            "Serve /.well-known/oauth-protected-resource (and the resource-path variant) with at least `resource` and `authorization_servers`, or advertise it via the resource_metadata parameter in the 401 challenge.",
          limitations: [
            "Discovery was attempted only on well-known paths and the advertised hint URL.",
            "A non-standard discovery mechanism would not be detected.",
          ],
          evidence: [
            { kind: "derived", locator: "GET /.well-known/oauth-protected-resource* → not found" },
          ],
        },
      ];
    },
  },

  {
    id: "AUTH-004",
    title: "401 challenge omits resource_metadata",
    owasp: ["MCP07"],
    taxonomy: ["authentication", "interoperability"],
    rationale:
      "The 401 challenge is the fastest path to discovery: clients read resource_metadata from it instead of guessing well-known locations.",
    run(probe) {
      if (probe.auth.statusOnUnauthenticatedInitialize !== 401) return [];
      if (probe.auth.resourceMetadataUrl) return [];
      return [
        {
          severity: "low",
          confidence: "high",
          assertion: "observed",
          observation: `The unauthenticated request returned 401 with a WWW-Authenticate header that does not include resource_metadata (header: ${probe.auth.wwwAuthenticate ?? "absent"}).`,
          inference:
            "Clients must fall back to guessing well-known metadata locations, which adds a failure mode.",
          recommendation:
            "Include resource_metadata=\"https://<host>/.well-known/oauth-protected-resource<path>\" in the 401 challenge.",
          limitations: ["Only the first unauthenticated challenge was inspected."],
          evidence: [{ kind: "http", locator: `POST ${probe.target} → 401` }],
        },
      ];
    },
  },
];
