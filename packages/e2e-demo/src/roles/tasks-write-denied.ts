import { defineRole } from "@aooth/arbac";

import type { ArbacDbScope, UserAttrs } from "./attrs";

// Wildcard-action deny: blocks every action on `tasks` in a single rule.
// Pins arbac-core's binary-deny contract — a deny matched by
// `_actionRegex.test(action)` short-circuits BEFORE scope evaluation
// (see arbac-core/src/arbac.ts:127-131), so any concurrent allow
// (member's row-level scope on tasks.markDone, admin's tasks.delete, etc.)
// CANNOT widen visibility back. A future change to deny that introduced
// scope-aware partial denies would silently start letting some rows
// through here — UNION-05 catches that drift.
//
// `*` compiles via `globToRegex` (arbac-core/src/utils.ts) to `[^.]*`,
// matching every non-dot action name (`markDone`, `new`, `delete`, …)
// in one rule — proving the regex matches MULTIPLE actions, not just
// the literal pattern string.
export const tasksWriteDeniedRole = defineRole<UserAttrs, ArbacDbScope>()
  .id("tasks-write-denied")
  .name("Tasks Write Denied")
  .describe("Hard-denies every action on tasks; composes to pin binary-deny short-circuit")
  .deny("tasks", "*")
  .build();
