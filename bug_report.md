# Bug Report: `updateOne` does not accept unique index fields as filter key

## Package

`@atscript/db` v0.1.41

## Description

`AtscriptDbTable.updateOne()` rejects payloads that identify a record by a unique-indexed field instead of the primary key. The error thrown is:

```
DbError: Missing primary key field "id" in payload
```

According to the documented behavior, `updateOne` should accept **PK or any unique index** in the payload to identify which record to update.

## Reproduction

### Schema (`.as` model)

```
@db.table 'aooth_users'
export interface AoothUserCredentials {
    @meta.id
    @db.default.uuid
    id: string

    @db.index.unique 'username_idx'
    username: string

    @db.patch.strategy 'merge'
    account: {
        active: boolean
        locked: boolean
        ...
    }
}
```

### Code

```typescript
const table = new AtscriptDbTable(AoothUserCredentials, adapter);
await table.ensureTable();
await table.syncIndexes();

// Insert a record
await table.insertOne({ id: "abc", username: "alice", account: { active: false, locked: false, ... } });

// Update by unique index field — FAILS
await table.updateOne({ username: "alice", account: { active: true } });
// => DbError: Missing primary key field "id" in payload
```

### Expected

`updateOne` should extract the filter from the `username` field (which has `@db.index.unique`) and produce:

```sql
UPDATE aooth_users SET account__active = 1 WHERE username = 'alice'
```

### Actual

`_extractPrimaryKeyFilter` only looks for the PK field (`id`) and throws when it's absent, ignoring unique index fields that could equally identify a single record.

## Additional context

### Related issue: nested `$inc` not detected by `updateMany`

`updateMany` calls `separateFieldOps(dataCopy)` **before** `prepareForWrite` flattens nested objects. Since `separateFieldOps` only scans top-level keys, `$inc` nested inside objects (e.g. `{ account: { failedLoginAttempts: { $inc: 1 } } }`) is not detected as an atomic operation and gets stored as a literal JSON string `'{"$inc":1}'`.

In contrast, `bulkUpdate` (used by `updateOne`) calls `decomposePatch` first which flattens the object, then runs `separateFieldOps` on the flattened result — so `$inc` is correctly detected at the top level.

This means there is currently **no working path** for atomic `$inc` on nested fields when identifying records by a unique index:

- `updateOne` — handles nested `$inc` (via decomposePatch), but rejects unique index filter keys
- `updateMany` — accepts any filter, but doesn't detect nested `$inc`

### Suggested fix

Either:

1. Extend `_extractPrimaryKeyFilter` in `bulkUpdate` to fall back to unique index fields when PK is absent
2. Move `separateFieldOps` in `updateMany` to run **after** `prepareForWrite` flattens nested objects (or add a recursive nested scan)

Option 1 would unblock the use case immediately.
