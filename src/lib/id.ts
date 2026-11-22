import { createHash } from "node:crypto";

/** SHA-256, hex. Used to make evidence immutable and verifiable. */
export function sha256(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

/** Short, stable identifier for findings and file names. */
export function shortHash(input: string, length = 12): string {
  return sha256(input).slice(0, length);
}

/**
 * Deterministic UUIDv5 (RFC 4122) over a fixed namespace.
 * STIX 2.1 requires UUIDv4 or UUIDv5 for object IDs; v5 keeps re-runs
 * idempotent, which matters when a bundle is re-generated every day.
 */
const NAMESPACE = "b1e7a3c4-5d6f-5a8b-9c0d-1e2f3a4b5c6d";

export function uuidv5(name: string, namespace: string = NAMESPACE): string {
  const ns = Buffer.from(namespace.replace(/-/g, ""), "hex");
  const hash = createHash("sha1")
    .update(ns)
    .update(Buffer.from(name, "utf8"))
    .digest();
  const bytes = Buffer.from(hash.subarray(0, 16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x50;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function slugify(input: string, maxLength = 48): string {
  const slug = input
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug.slice(0, maxLength) || "target";
}
