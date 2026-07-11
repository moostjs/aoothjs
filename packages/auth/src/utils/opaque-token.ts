import { randomBytes } from "node:crypto";

/**
 * 32 bytes of CSPRNG entropy (256 bits) encoded as base64url — 43 chars,
 * URL-safe. The single mint for every opaque bearer-style secret in the stack
 * (magic-link tokens, dynamic-client secrets, authz browser bindings):
 * unguessable online, cheap to generate, safe to place in a URL.
 */
export function generateOpaqueToken(): string {
  return randomBytes(32).toString("base64url");
}
