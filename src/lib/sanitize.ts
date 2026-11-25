/**
 * Untrusted text ends up in a terminal and in an HTML document.
 *
 * A server controls its tool names, descriptions, schemas and error strings, so
 * a report is an injection surface: ANSI escapes can clear the screen, set the
 * window title, or hide text; bidi controls can reorder it.
 *
 * The raw record keeps the bytes — it is evidence. Sanitisation happens at the
 * rendering boundary, where the risk is.
 */

// C0 and C1 except tab (0x09), newline (0x0A) and carriage return (0x0D).
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
// Zero-width, bidi overrides and other invisible formatting.
const INVISIBLE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;
// Unicode tag characters, used to smuggle invisible instructions.
const TAG = /[\u{E0000}-\u{E007F}]/gu;

/** Removes characters that can steer a terminal, keeping layout whitespace. */
export function stripUnsafe(input: string): string {
  return input.replace(CONTROL, "").replace(INVISIBLE, "").replace(TAG, "");
}

/** Removes unsafe characters and bounds the length. */
export function sanitizeText(input: string, max = 4_000): string {
  const stripped = stripUnsafe(input);
  if (stripped.length <= max) return stripped;
  return `${stripped.slice(0, max)}… [truncated ${input.length - max} chars]`;
}
