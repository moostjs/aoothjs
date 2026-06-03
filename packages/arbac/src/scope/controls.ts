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

/**
 * Conjoin two ALREADY-UNIONED controls policies (each the output of
 * {@link unionControlsPolicy} for one authority pass) under DENY-WINS
 * intersection — a control is permitted only if BOTH passes permit it. This is
 * the credential-attenuation combiner; polarity is the **opposite** of
 * {@link unionControlsPolicy} (which is additive / silence-wins).
 *
 * Per control key (absent ≡ allowed, matching {@link unionControlsPolicy}):
 *   - denied (`false`) on EITHER side → `false`.
 *   - allowed on one side → the OTHER side's gate (`allow ∧ X = X`).
 *   - whitelist ∧ whitelist → the INTERSECTION of the two arrays (only values
 *     allowed by both; may be empty = nothing permitted).
 *
 * @returns merged policy; keys absent from the result mean "allowed" (callers
 *          treat a missing key as `true`), matching {@link unionControlsPolicy}.
 */
export function intersectControlsPolicy(
  a: Record<string, ControlGate>,
  b: Record<string, ControlGate>,
): Record<string, ControlGate> {
  const result: Record<string, ControlGate> = {};
  const keys = new Set<string>([...Object.keys(a), ...Object.keys(b)]);
  for (const key of keys) {
    const av: ControlGate = key in a ? a[key] : true; // absent ≡ allowed
    const bv: ControlGate = key in b ? b[key] : true;
    if (av === false || bv === false) {
      result[key] = false; // deny-wins
      continue;
    }
    if (av === true) {
      if (Array.isArray(bv)) result[key] = [...bv]; // allow ∧ whitelist = whitelist
      continue;
    }
    if (bv === true) {
      if (Array.isArray(av)) result[key] = [...av];
      continue;
    }
    // both whitelists → intersection (only values admitted by both)
    const bset = new Set(bv);
    result[key] = [...new Set(av)].filter((v) => bset.has(v)).toSorted();
  }
  return result;
}
