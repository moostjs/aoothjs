```ts:no-line-numbers
import {
  Arbac,
  defineRole,
  allowTableRead,
  allowTableWrite,
} from "@aooth/arbac";

type Attrs = { tenantId: string; department: string };
type Scope = { filter?: { tenantId?: string; department?: string } };

const manager = defineRole<Attrs, Scope>()
  .id("com.role.manager")
  .use(
    allowTableWrite("articles", {
      scope: (a) => ({ filter: { department: a.department } }),
    }),
  )
  .use(allowTableRead("reports"))
  .deny("articles", "publish")
  .build();

const arbac = new Arbac<Attrs, Scope>();
arbac.registerRole(manager);

const result = await arbac.evaluate(
  { resource: "articles", action: "update" },
  { id: "u1", roles: ["com.role.manager"], attrs },
);
// → { allowed: true, scopes: [{ filter: { department: "sales" } }] }
```
