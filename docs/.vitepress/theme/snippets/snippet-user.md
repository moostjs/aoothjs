```ts:no-line-numbers
import { UserService } from "@aoothjs/user";
import {
  UsersStoreAtscriptDb,
  type AuthUserTable,
} from "@aoothjs/user/atscript-db";
import {
  ppHasMinLength,
  ppHasUpperCase,
  ppHasNumber,
} from "@aoothjs/user";

const users = new UserService(
  new UsersStoreAtscriptDb({
    table: db.getTable(AppUser) as unknown as AuthUserTable,
  }),
  {
    password: {
      pepper: process.env.PEPPER!,
      historyLength: 5,
      policies: [ppHasMinLength(12), ppHasUpperCase(1), ppHasNumber(1)],
    },
    lockout: { threshold: 5, duration: 15 * 60_000 },
  },
);

await users.createUser("alice@app.dev", "P4ssphrase!");
const { user, mfaRequired } = await users.login(
  "alice@app.dev",
  "P4ssphrase!",
);
```
