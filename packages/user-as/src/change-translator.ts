import type { TCumulativeChanges } from "@aoothjs/user";

/**
 * Translates TCumulativeChanges (dotted paths with set/unset/inc ops)
 * into a nested partial object suitable for AtscriptDbTable.updateOne().
 *
 * - set  → value at nested path
 * - unset → null at nested path
 * - inc  → { $inc: amount } at nested path (atomic, @atscript/db >=0.1.41)
 */
export function translateChanges(changes: TCumulativeChanges): Record<string, unknown> | null {
  const entries = Object.entries(changes);
  if (entries.length === 0) return null;

  const result: Record<string, unknown> = {};

  for (const [dottedPath, change] of entries) {
    switch (change.op) {
      case "set":
        setNestedValue(result, dottedPath, change.value);
        break;
      case "unset":
        setNestedValue(result, dottedPath, null);
        break;
      case "inc":
        setNestedValue(result, dottedPath, { $inc: change.value as number });
        break;
    }
  }

  return result;
}

function setNestedValue(obj: Record<string, unknown>, path: string, value: unknown): void {
  const parts = path.split(".");
  let current: Record<string, unknown> = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (current[parts[i]] === undefined || current[parts[i]] === null) {
      current[parts[i]] = {};
    }
    current = current[parts[i]] as Record<string, unknown>;
  }
  current[parts[parts.length - 1]] = value;
}
