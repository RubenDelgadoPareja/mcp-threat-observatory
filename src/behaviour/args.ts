/**
 * Deterministic argument generation from a tool's JSON Schema.
 *
 * Determinism is the point: the same schema, seed and profile must produce the
 * same arguments on every run, so a behaviour record can be reproduced by
 * someone who was not there. No model is involved, by design.
 *
 * Two profiles:
 *   - `neutral`   describes the tool's default behaviour ("mcpobs-test").
 *   - `targeted`  substitutes credential-shaped paths and URLs for parameters
 *                 that look like a path or a URL, to test whether the server
 *                 stays inside its configured root. The files it points at are
 *                 canaries in a temporary HOME, never real credentials.
 */

export type ArgumentProfile = "neutral" | "targeted";

export interface ArgumentContext {
  profile?: ArgumentProfile;
  /** Absolute paths of planted canary files. */
  canaryPaths?: string[];
  /** A host that does not exist, used for URL-shaped parameters. */
  canaryUrl?: string;
}

export interface GeneratedArguments {
  arguments: Record<string, unknown>;
  /** Choices that could not honour the schema, and therefore may explain a tool error. */
  notes: string[];
}

const FIXED = {
  email: "mcpobs@example.test",
  uri: "https://example.test/resource",
  url: "https://example.test/resource",
  uuid: "00000000-0000-4000-8000-000000000000",
  "date-time": "2026-01-01T00:00:00Z",
  date: "2026-01-01",
  time: "00:00:00",
};

const PATH_KEY = /(^|[_-])(path|file|filepath|filename|dir|directory|folder|root|target|source|dest|destination)([_-]|$)/i;
const URL_KEY = /(url|uri|endpoint|host|webhook|link)/i;

function pickFromEnum(values: unknown[], seed: number): unknown {
  if (values.length === 0) return null;
  const index = (seed - 1) % values.length;
  return values[index < 0 ? 0 : index];
}

function targetedKind(name: string, schema: Record<string, unknown>): "path" | "url" | null {
  const format = typeof schema.format === "string" ? schema.format : "";
  if (format === "uri" || format === "uri-reference" || format === "url") return "url";
  if (URL_KEY.test(name)) return "url";
  if (PATH_KEY.test(name)) return "path";
  return null;
}

function stringValue(
  schema: Record<string, unknown>,
  seed: number,
  notes: string[],
  locator: string,
  name: string,
  context: ArgumentContext,
): string {
  if (Array.isArray(schema.enum) && schema.enum.length > 0) {
    const chosen = pickFromEnum(schema.enum, seed);
    return typeof chosen === "string" ? chosen : JSON.stringify(chosen);
  }

  if (context.profile === "targeted") {
    const kind = targetedKind(name, schema);
    if (kind === "path" && context.canaryPaths?.length) {
      notes.push(`${locator}: targeted profile substituted a canary path for \`${name}\``);
      return context.canaryPaths[0]!;
    }
    if (kind === "url" && context.canaryUrl) {
      notes.push(`${locator}: targeted profile substituted a canary URL for \`${name}\``);
      return context.canaryUrl;
    }
  }

  const format = typeof schema.format === "string" ? schema.format : undefined;
  if (format && format in FIXED) {
    let value = FIXED[format as keyof typeof FIXED];
    if (typeof schema.maxLength === "number") value = value.slice(0, schema.maxLength);
    return value;
  }
  if (typeof schema.pattern === "string") {
    notes.push(`${locator}: pattern ${schema.pattern} cannot be synthesised; used a plain string`);
  }
  let value = "mcpobs-test";
  if (typeof schema.maxLength === "number" && schema.maxLength < value.length) {
    value = value.slice(0, Math.max(0, schema.maxLength));
  }
  if (typeof schema.minLength === "number" && value.length < schema.minLength) {
    value = value.padEnd(schema.minLength, "x");
  }
  return value;
}

function numberValue(schema: Record<string, unknown>): number {
  if (typeof schema.default === "number") return schema.default;
  const minimum = typeof schema.minimum === "number" ? schema.minimum : 1;
  const exclusive = typeof schema.exclusiveMinimum === "number" ? schema.exclusiveMinimum + 1 : undefined;
  let value = exclusive ?? minimum;
  if (typeof schema.maximum === "number") value = Math.min(value, schema.maximum);
  return value;
}

function valueFor(
  schema: unknown,
  seed: number,
  notes: string[],
  locator: string,
  name: string,
  context: ArgumentContext,
): unknown {
  if (!schema || typeof schema !== "object") return "mcpobs-test";
  const node = schema as Record<string, unknown>;

  if ("const" in node) return node.const;
  if (typeof node.default !== "undefined" && context.profile !== "targeted") return node.default;

  for (const key of ["oneOf", "anyOf"] as const) {
    if (Array.isArray(node[key]) && node[key].length > 0) {
      return valueFor((node[key] as unknown[])[0], seed, notes, `${locator}.${key}[0]`, name, context);
    }
  }

  const type = typeof node.type === "string" ? node.type : Array.isArray(node.type) ? node.type[0] : undefined;
  switch (type) {
    case "string":
      return stringValue(node, seed, notes, locator, name, context);
    case "integer":
      return Math.trunc(numberValue(node));
    case "number":
      return numberValue(node);
    case "boolean":
      // Least invasive choice: a sandbox should not opt into destructive behaviour.
      return false;
    case "array":
      notes.push(`${locator}: array left empty to avoid inventing elements`);
      return [];
    case "object":
      return objectValue(node, seed, notes, locator, context).arguments;
    default:
      return "mcpobs-test";
  }
}

function objectValue(
  schema: Record<string, unknown>,
  seed: number,
  notes: string[],
  locator: string,
  context: ArgumentContext,
): GeneratedArguments {
  const out: Record<string, unknown> = {};
  const properties =
    schema.properties && typeof schema.properties === "object"
      ? (schema.properties as Record<string, unknown>)
      : {};
  const required = Array.isArray(schema.required)
    ? schema.required.filter((key): key is string => typeof key === "string")
    : [];

  // In the targeted profile, a path or URL parameter is interesting even when
  // optional: that is exactly where confinement is tested.
  const optional = Object.keys(properties).filter((key) => !required.includes(key));
  const targetedOptional =
    context.profile === "targeted"
      ? optional.filter((key) => {
          const node = properties[key];
          return !!node && typeof node === "object" && targetedKind(key, node as Record<string, unknown>) !== null;
        })
      : [];
  const emittedOptional = targetedOptional;

  for (const key of [...required, ...emittedOptional]) {
    if (!(key in properties)) {
      notes.push(`${locator}.${key}: required but not declared in properties`);
      continue;
    }
    out[key] = valueFor(properties[key], seed, notes, `${locator}.${key}`, key, context);
  }

  const omitted = optional.filter((key) => !emittedOptional.includes(key));
  if (omitted.length > 0) {
    notes.push(`${locator}: omitted optional ${omitted.join(", ")} to keep the call minimal`);
  }
  if (schema.additionalProperties === true) {
    notes.push(`${locator}: schema allows additional properties; none were sent`);
  }
  return { arguments: out, notes };
}

/** Generates the arguments for one tool call. */
export function generateArguments(
  schema: unknown,
  seed = 1,
  context: ArgumentContext = {},
): GeneratedArguments {
  if (!schema || typeof schema !== "object") {
    return { arguments: {}, notes: ["no input schema: called with no arguments"] };
  }
  const node = schema as Record<string, unknown>;
  if (node.type !== "object") {
    return {
      arguments: { value: valueFor(node, seed, [], "value", "value", context) },
      notes: ["schema is not an object; wrapped the generated value under `value`"],
    };
  }
  const { arguments: args, notes } = objectValue(node, seed, [], "$", context);
  return { arguments: args, notes };
}
