import type { ProbeResult, ToolDescriptor } from "../model.ts";

export interface CapabilityProfile {
  /** Tools that can execute code, destroy data, move money, or escalate. */
  highImpact: string[];
  /** Tools that read data an operator would consider private. */
  privateData: string[];
  /** Tools that can send data to a destination the operator does not control. */
  egress: string[];
  /** Tools that accept unstructured remote input (URLs, free text). */
  freeTextIngress: string[];
}

const EXEC = /\b(exec|execute|shell|bash|sh|cmd|command|script|spawn|eval|run)\b/i;
const DESTRUCTIVE = /(delete|drop|destroy|truncate|purge|wipe|remove|unlink|rm_)/i;
const PAYMENT = /(payment|transfer|purchase|charge|refund|billing|checkout|wire)/i;
const ADMIN = /(admin|sudo|root|privilege|impersonate|impersonation|grant|revoke)/i;
const PRIVATE_DATA =
  /(file|document|doc|db|database|sql|mail|email|message|chat|secret|credential|token|user|customer|invoice|ledger|memory|note|record|contact|calendar|repo|source)/i;
const READ = /(read|get|list|fetch|search|query|download|export|dump|show|view|find)/i;
const EGRESS = /(send|post|upload|publish|forward|webhook|reply|tweet|sms|notify|email|share)/i;
const INGRESS = /(search|fetch|read|browse|scrape|parse|open|load|import|input|url|web|page)/i;

function text(tool: ToolDescriptor): string {
  return [tool.name, tool.title ?? "", tool.description ?? ""].join(" ");
}

/** Walks a JSON Schema and yields string-valued keywords with their path. */
export function collectSchemaStrings(
  schema: unknown,
  path = "$",
): Array<{ path: string; text: string }> {
  const out: Array<{ path: string; text: string }> = [];
  if (!schema || typeof schema !== "object") return out;
  const node = schema as Record<string, unknown>;

  for (const key of ["title", "description", "$comment"]) {
    if (typeof node[key] === "string") out.push({ path: `${path}.${key}`, text: node[key] as string });
  }
  if (typeof node.default === "string") out.push({ path: `${path}.default`, text: node.default });

  if (Array.isArray(node.enum)) {
    node.enum.forEach((value, index) => {
      if (typeof value === "string") out.push({ path: `${path}.enum[${index}]`, text: value });
    });
  }

  if (node.properties && typeof node.properties === "object") {
    for (const [name, child] of Object.entries(node.properties as Record<string, unknown>)) {
      out.push(...collectSchemaStrings(child, `${path}.properties.${name}`));
    }
  }
  if (Array.isArray(node.items)) {
    node.items.forEach((child, index) => out.push(...collectSchemaStrings(child, `${path}.items[${index}]`)));
  } else if (node.items) {
    out.push(...collectSchemaStrings(node.items, `${path}.items`));
  }
  for (const key of ["anyOf", "oneOf", "allOf"]) {
    const variants = node[key];
    if (Array.isArray(variants)) {
      variants.forEach((child, index) => out.push(...collectSchemaStrings(child, `${path}.${key}[${index}]`)));
    }
  }
  return out;
}

/** Returns true when a JSON Schema for a tool allows arbitrary string input. */
export function hasUnconstrainedString(schema: unknown): boolean {
  let found = false;
  const walk = (node: unknown): void => {
    if (found || !node || typeof node !== "object") return;
    const n = node as Record<string, unknown>;
    if (n.type === "string") {
      const constrained =
        Array.isArray(n.enum) ||
        typeof n.pattern === "string" ||
        typeof n.maxLength === "number" ||
        typeof n.format === "string";
      if (!constrained) {
        found = true;
        return;
      }
    }
    if (n.properties && typeof n.properties === "object") {
      Object.values(n.properties as Record<string, unknown>).forEach(walk);
    }
    if (n.items) walk(n.items);
    for (const key of ["anyOf", "oneOf", "allOf"]) {
      if (Array.isArray(n[key])) (n[key] as unknown[]).forEach(walk);
    }
  };
  walk(schema);
  return found;
}

export function classifyCapabilities(tools: ToolDescriptor[] | null): CapabilityProfile {
  const profile: CapabilityProfile = {
    highImpact: [],
    privateData: [],
    egress: [],
    freeTextIngress: [],
  };
  if (!tools) return profile;

  for (const tool of tools) {
    const haystack = text(tool);
    const annotations = tool.annotations ?? {};

    if (
      annotations.destructiveHint === true ||
      EXEC.test(haystack) ||
      DESTRUCTIVE.test(haystack) ||
      PAYMENT.test(haystack) ||
      ADMIN.test(haystack)
    ) {
      profile.highImpact.push(tool.name);
    }
    if (READ.test(haystack) && PRIVATE_DATA.test(haystack)) {
      profile.privateData.push(tool.name);
    }
    if (EGRESS.test(haystack) || annotations.openWorldHint === true) {
      profile.egress.push(tool.name);
    }
    if (INGRESS.test(haystack) && hasUnconstrainedString(tool.inputSchema)) {
      profile.freeTextIngress.push(tool.name);
    }
  }

  const uniq = (values: string[]): string[] => [...new Set(values)];
  profile.highImpact = uniq(profile.highImpact);
  profile.privateData = uniq(profile.privateData);
  profile.egress = uniq(profile.egress);
  profile.freeTextIngress = uniq(profile.freeTextIngress);
  return profile;
}

/** Convenience: all metadata text a model would see for a catalog. */
export function catalogText(probe: ProbeResult): Array<{ path: string; text: string }> {
  const out: Array<{ path: string; text: string }> = [];
  for (const tool of probe.tools ?? []) {
    const base = `tools[${tool.name}]`;
    if (tool.title) out.push({ path: `${base}.title`, text: tool.title });
    if (tool.description) out.push({ path: `${base}.description`, text: tool.description });
    out.push(...collectSchemaStrings(tool.inputSchema, `${base}.inputSchema`));
  }
  return out;
}
