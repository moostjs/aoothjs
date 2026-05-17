import { allowTableRead, defineRole } from "@aoothjs/arbac";

import { DemoUser } from "../models/user.as";
import type { ArbacDbScope, UserAttrs } from "./attrs";
import { PROJ_USER_SELF } from "./projections";

export const guestRole = defineRole<UserAttrs, ArbacDbScope>()
  .id("guest")
  .name("Guest")
  .describe("Login only; read own user record")
  .use(
    allowTableRead<UserAttrs, ArbacDbScope<DemoUser>>("users", {
      scope: (_attrs, userId) => ({
        filter: { username: userId },
        projection: PROJ_USER_SELF,
      }),
    }),
  )
  .build();
