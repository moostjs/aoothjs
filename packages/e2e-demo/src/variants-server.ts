/**
 * Server-only entry point for the variant-config layer. Kept separate from
 * `./variants` so the Vue client bundle (which imports the variant maps from
 * `HomePage.vue`) doesn't drag in `@wooksjs/event-http` (and its `node:async_hooks`
 * dependency) through the dev server.
 */
import { useHeaders } from "@wooksjs/event-http";

/**
 * Reads the `x-wf-variant` request header. Wrapped in try/catch because the
 * workflow subclass constructors that call this also run during moost's
 * non-HTTP DI resolution phase, where `useHeaders()` throws.
 */
export function readVariantHeader(): string | null {
  try {
    const raw = useHeaders()["x-wf-variant"];
    if (typeof raw === "string") return raw;
    if (Array.isArray(raw) && typeof raw[0] === "string") return raw[0];
    return null;
  } catch {
    return null;
  }
}
