import { defineRole } from "@aoothjs/arbac";

import type { UserAttrs } from "./attrs";

// Single-purpose deny role: blocks `comments.query`. Composed with `member`
// (which would otherwise allow comments reads), it lets UNION-03 assert
// `effect: 'deny'` short-circuits an additive union — i.e. the strongest
// allow doesn't override an explicit deny on the same (resource, action).
//
// Shape stays minimal so the test can assign this role + member to a user
// at runtime without dragging extra fixtures into the seed.
export const commentsDeniedRole = defineRole<UserAttrs>()
  .id("comments-denied")
  .name("Comments Denied")
  .describe(
    "Hard-denies reading comments; composes with other roles to exercise deny short-circuit",
  )
  .deny("comments", "query")
  .build();
