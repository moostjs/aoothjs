import { defineRole, tableReadPrivilege } from "@aoothjs/arbac"

import type { ArbacDbScope, UserAttrs } from "./attrs"
import { PROJ_USER_SELF } from "./projections"

export const guestRole = defineRole<UserAttrs, ArbacDbScope>()
  .id("guest")
  .name("Guest")
  .describe("Login only; read own user record (for /auth/status)")
  .use(
    tableReadPrivilege<UserAttrs, ArbacDbScope>("users", {
      scope: (_attrs, userId) => ({
        filter: { username: userId },
        projection: PROJ_USER_SELF,
      }),
    }),
  )
  .build()
