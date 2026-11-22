/**
 * Text inspection for metadata that may be aimed at a model rather than a
 * human. Kept deliberately small and explicit: every rule here is a signal,
 * not a verdict. Callers must report findings as `inferred` with low or
 * moderate confidence and require human review.
 */

export interface TextAnomaly {
  kind: "hidden-character" | "bidi-control" | "tag-character" | "instruction-override" | "credential-path" | "exfiltration-wording";
  /** Character offset in the normalized text, when meaningful. */
  index?: number;
  codepoint?: string;
  match: string;
  note: string;
}

const ZERO_WIDTH = new Set([
  0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x2060, 0xfeff, 0x180e,
]);

const BIDI = new Set([
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069,
]);

function isTagChar(cp: number): boolean {
  return cp >= 0xe0000 && cp <= 0xe007f;
}

/**
 * Instruction-override phrases. Precision-first: these are narrow patterns
 * that rarely appear in honest tool documentation. Broad keywords ("ignore",
 * "system") were deliberately excluded because they generate noise.
 */
const INSTRUCTION_PATTERNS: Array<{ re: RegExp; note: string }> = [
  { re: /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/gi, note: "instruction override" },
  { re: /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|rules)/gi, note: "instruction override" },
  { re: /do\s+not\s+(tell|inform|mention\s+to)\s+the\s+user/gi, note: "asks to conceal behaviour from the user" },
  { re: /without\s+(telling|informing|notifying)\s+the\s+user/gi, note: "asks to conceal behaviour from the user" },
  { re: /instead\s+of\s+(using|calling)\s+[a-z0-9_\-]+/gi, note: "redirects the model away from another tool" },
  { re: /<\s*important\s*>/gi, note: "known injection marker" },
  { re: /<\s*\/?\s*system\s*>/gi, note: "fake system boundary" },
  { re: /^\s*(system|assistant)\s*:/gi, note: "fake conversation role" },
];

const CREDENTIAL_PATTERNS: Array<{ re: RegExp; note: string }> = [
  { re: /\.ssh\/id_(rsa|ed25519|ecdsa|dsa)/gi, note: "references an SSH private key" },
  { re: /\.aws\/credentials/gi, note: "references AWS credentials" },
  { re: /(^|[^a-z])\.env([^a-z]|$)/gi, note: "references a .env file" },
  { re: /id_rsa/gi, note: "references an SSH private key" },
  { re: /\.npmrc/gi, note: "references the npm token file" },
  { re: /\.git-credentials/gi, note: "references stored git credentials" },
];

const EXFIL_PATTERNS: Array<{ re: RegExp; note: string }> = [
  { re: /\b(base64|hex)\s*(encode|encoded)\b/gi, note: "encoding step often used before exfiltration" },
  { re: /\bpost\s+(the\s+)?(contents?|output|data)\s+to\s+https?:\/\//gi, note: "sends data to a remote endpoint" },
  { re: /\b(send|upload|forward)\s+(it|them|the\s+.*?)\s+to\s+[\w.@-]+\.[a-z]{2,}/gi, note: "sends data to an external address" },
];

/**
 * Normalizes text for comparison (NFKC, whitespace) and returns the
 * anomalies found in the *original* text. Hidden characters are detected on
 * the raw string because normalization would erase them.
 */
export function scanMetadataText(input: string): TextAnomaly[] {
  const anomalies: TextAnomaly[] = [];

  for (const ch of input) {
    const cp = ch.codePointAt(0)!;
    if (ZERO_WIDTH.has(cp)) {
      anomalies.push({
        kind: "hidden-character",
        codepoint: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
        match: ch,
        note: "invisible character can hide text from human review",
      });
    } else if (BIDI.has(cp)) {
      anomalies.push({
        kind: "bidi-control",
        codepoint: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
        match: ch,
        note: "bidirectional control can reorder displayed text",
      });
    } else if (isTagChar(cp)) {
      anomalies.push({
        kind: "tag-character",
        codepoint: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
        match: ch,
        note: "Unicode tag characters are used to smuggle invisible instructions",
      });
    }
  }

  for (const { re, note } of INSTRUCTION_PATTERNS) {
    for (const m of input.matchAll(re)) {
      anomalies.push({ kind: "instruction-override", index: m.index, match: m[0], note });
    }
  }
  for (const { re, note } of CREDENTIAL_PATTERNS) {
    for (const m of input.matchAll(re)) {
      anomalies.push({ kind: "credential-path", index: m.index, match: m[0], note });
    }
  }
  for (const { re, note } of EXFIL_PATTERNS) {
    for (const m of input.matchAll(re)) {
      anomalies.push({ kind: "exfiltration-wording", index: m.index, match: m[0], note });
    }
  }

  return anomalies;
}

/** Collapses duplicate anomalies of the same kind and match. */
export function dedupeAnomalies(anomalies: TextAnomaly[]): TextAnomaly[] {
  const seen = new Set<string>();
  const out: TextAnomaly[] = [];
  for (const a of anomalies) {
    const key = `${a.kind}|${a.match}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(a);
  }
  return out;
}

/** Safe, bounded excerpt for evidence blocks. */
export function excerpt(input: string, max = 800): string {
  const flat = input.replace(/\s+/g, " ").trim();
  return flat.length <= max ? flat : `${flat.slice(0, max)}…`;
}
