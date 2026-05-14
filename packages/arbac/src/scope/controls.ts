import type { ControlGate } from "./types";

/**
 * Controls whose values can be sensibly whitelisted via `readonly string[]`.
 *
 * - `$with` — relation names; uniquery parses to `{ name, … }[]`.
 * - `$groupBy` — column names; the value already IS the array of names.
 *
 * Other controls only support boolean gates in v1; supplying a whitelist
 * for them throws from {@link unionControlsPolicy}.
 */
const WHITELISTABLE_CONTROLS: ReadonlySet<string> = new Set(["$with", "$groupBy"]);

/**
 * Union per-role `controls` policies. Additive RBAC semantics: more roles =
 * broader access, mirroring how `mergeScopeFilters` and `unionProjections`
 * combine other parts of an `ArbacDbScope`.
 *
 * Resolution per control key:
 *   1. Collect each scope's value for the key (including `undefined` for
 *      silent scopes — i.e., scopes that have a `controls` map but no entry
 *      for this key).
 *   2. If any value is `undefined` or `true` → return `true` (full allow).
 *      Silence and explicit allow both mean "this role has no objection".
 *   3. Else (every scope is `false` or `string[]`):
 *      - If all are `false` → return `false` (full deny).
 *      - Else collect every `string[]` into a single sorted, de-duplicated
 *        array; return that array. (Roles that say `false` don't contribute
 *        positively; roles with whitelists do.)
 *
 * Scopes that omit the `controls` map entirely are treated as silent on
 * EVERY key — i.e., they grant unrestricted control usage. As a result, if
 * even a single scope in the input lacks a `controls` map, the result is
 * always `{}` (no restrictions).
 *
 * Whitelist support is restricted to {@link WHITELISTABLE_CONTROLS}. Passing
 * a whitelist for any other control throws — the gate cannot be enforced
 * meaningfully in v1, so the misuse is rejected loudly at scope-merge time.
 *
 * @returns merged policy keyed by control name. Keys absent from the result
 *          mean "no opinion → fully allowed". The caller should treat a
 *          missing key the same as `true`.
 *
 * @throws when a non-whitelistable control is given a `readonly string[]` gate.
 */
export function unionControlsPolicy(
  scopes: ReadonlyArray<{ controls?: Record<string, ControlGate> }>,
): Record<string, ControlGate> {
  if (scopes.length === 0) return {};

  // If any scope has no `controls` map at all, it's silent on everything →
  // full universe grant. Mirrors `mergeScopeFilters` returning `undefined`
  // when any scope filter is empty.
  if (scopes.some((s) => !s.controls)) return {};

  // Collect the union of keys mentioned by any scope.
  const allKeys = new Set<string>();
  for (const s of scopes) {
    for (const k of Object.keys(s.controls!)) allKeys.add(k);
  }

  const result: Record<string, ControlGate> = {};
  for (const key of allKeys) {
    let anyAllow = false;
    const whitelistAcc = new Set<string>();
    let hadWhitelist = false;

    for (const s of scopes) {
      const v = s.controls![key];
      if (v === undefined || v === true) {
        anyAllow = true;
        break;
      }
      if (v === false) continue;
      if (Array.isArray(v)) {
        if (!WHITELISTABLE_CONTROLS.has(key)) {
          throw new Error(
            `unionControlsPolicy: control "${key}" only supports boolean gates; whitelist arrays not yet implemented`,
          );
        }
        hadWhitelist = true;
        for (const item of v) whitelistAcc.add(item);
        continue;
      }
      // Defensive — type system already excludes other shapes.
      throw new Error(
        `unionControlsPolicy: invalid gate value ${String(v)} for control "${key}" (must be boolean or string[])`,
      );
    }

    // anyAllow → leave key absent (absent ≡ true ≡ allowed; keeps result minimal).
    if (anyAllow) continue;
    if (hadWhitelist) {
      result[key] = [...whitelistAcc].toSorted();
      continue;
    }
    // No allow, no whitelist → every scope said `false`. Full deny.
    result[key] = false;
  }

  return result;
}
