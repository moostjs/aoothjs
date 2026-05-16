# @aoothjs/user

User credential primitives for the aoothjs ecosystem. Pluggable
`UserStore`, password hashing + policy, lockout, MFA (TOTP, codes, backup
codes), and the `UserService` orchestrator.

## Install

```bash
pnpm add @aoothjs/user
```

## Storage adapters

The core package ships an in-memory `UserStoreMemory`. One additional
adapter is available as a subpath export — tree-shaken when not imported,
no extra deps in the core bundle.

### `@aoothjs/user/atscript-db`

`UserStore` backed by an `@atscript/db` table. Ship the `.as` model
alongside your other database models and pass the resolved table to the
adapter:

```ts
import { DbSpace } from "@atscript/db";
import { SqliteAdapter, BetterSqlite3Driver } from "@atscript/db-sqlite";
import { syncSchema } from "@atscript/db/sync";
import { AoothUserCredentials } from "@aoothjs/user/atscript-db/model.as";
import { UsersStoreAtscriptDb } from "@aoothjs/user/atscript-db";
import { UserService } from "@aoothjs/user";

const db = new DbSpace(() => new SqliteAdapter(new BetterSqlite3Driver("./app.db")));
await syncSchema(db, [AoothUserCredentials]);

const userStore = new UsersStoreAtscriptDb({ table: db.getTable(AoothUserCredentials) });
const userService = new UserService(userStore);
```

The shipped `.as` interface is the base credential record — no `@meta.id`,
no app-specific fields. Extend it in your own `.as` to add a primary key
and custom columns:

```ts
import { AoothUserCredentials } from '@aoothjs/user/atscript-db/model.as'

@db.table 'users'
export interface AppUser extends AoothUserCredentials {
    @meta.id
    @db.default.uuid
    id: string

    email?: string
}
```

`@atscript/db` is an optional `peerDependency` — installs only when you
actually wire the atscript-db store.

### Why no Redis adapter for users

Credentials are PII (password hashes, MFA secrets, account lock state,
backup codes). Redis is the wrong store for them: it is typically
in-memory with append-only persistence, not designed as a durable
system-of-record for sensitive identity data, and lacks the relational
constraints (FKs to tenants/orgs, transactional updates across user +
audit rows) that a real user table needs.

A Redis adapter is available for `@aoothjs/auth` because _credentials_
(short-lived session tokens) are a natural fit — high-churn, TTL-bound,
revocation by key. Long-lived user records are not.
