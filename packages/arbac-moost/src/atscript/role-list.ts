/**
 * Collect unique, non-empty strings from an iterable of unknown values,
 * preserving first-seen order and dropping anything that is not a non-empty
 * string. Shared by the user-side role extraction
 * (`AtscriptArbacUserProvider.extractRoles`) and the credential-side
 * attenuation role parse (`extractAttenuation`) so both apply identical
 * dedup / drop-empty rules.
 */
export function uniqueStrings(values: Iterable<unknown>): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of values) {
    if (typeof v === "string" && v !== "" && !seen.has(v)) {
      seen.add(v);
      out.push(v);
    }
  }
  return out;
}
