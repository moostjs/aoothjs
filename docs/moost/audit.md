# Audit Log

This page covers the audit event types, the events emitted by each workflow today, and how to wire a sink.

## Types

```ts
interface AuditEvent {
  kind: string;
  userId?: string;
  workflow?: string;
  ip?: string;
  userAgent?: string;
  [k: string]: unknown;
}

interface AuditEmitter {
  emit(event: AuditEvent): Promise<void> | void;
}
```

The `AuditEmitter` interface is exported but the package ships **no concrete sink**. Every workflow fires audit events through its `protected audit(event)` method (default no-op). You wire your sink by overriding `audit` on your workflow subclasses.

## Events emitted today

| Workflow           | Step                    | `kind`               | Extra fields                                                                                      |
| ------------------ | ----------------------- | -------------------- | ------------------------------------------------------------------------------------------------- |
| `LoginWorkflow`    | `audit-login`           | `login.success`      | `method` = `mfaMethod ?? 'mfa.skipped' ?? 'password'`, optional `tenantId`                        |
| `RecoveryWorkflow` | `recoveryRequest`       | `recovery.requested` | `email` (the requested address — emitted even on unknown addresses for anti-enumeration symmetry) |
| `RecoveryWorkflow` | `recoveryAudit`         | `recovery.completed` | `deliveryMode`, optional `sessionsRevoked`                                                        |
| `InviteWorkflow`   | invite Phase A          | `invite.created`     | invited `email`, `roles?`                                                                         |
| `InviteWorkflow`   | `auth.reInvite`         | `invite.resent`      | `email`                                                                                           |
| `InviteWorkflow`   | invite Phase B finalize | `invite.accepted`    | accepting `userId`                                                                                |
| `InviteWorkflow`   | `auth.cancelInvite`     | `invite.cancelled`   | cancelled `email`                                                                                 |

All events include the standard `userId`, `workflow`, `ip`, `userAgent` fields when the workflow has access to them.

## Wiring a sink

Override `audit` on each workflow subclass:

```ts
import { type AuditEvent, LoginWorkflow } from "@aoothjs/auth-moost";

@Inherit()
@Injectable("FOR_EVENT")
@Controller()
class MyLoginWorkflow extends LoginWorkflow {
  constructor(users: UserService, auth: AuthCredential) {
    super(myLoginOpts, users, auth);
  }
  protected override async audit(event: AuditEvent): Promise<void> {
    await auditTable.insert({
      ...event,
      at: new Date(),
    });
  }
}
```

Repeat for `MyRecoveryWorkflow` and `MyInviteWorkflow`. The three overrides will usually delegate to the same shared function:

```ts
const writeAudit = async (event: AuditEvent) => {
  await auditTable.insert({ ...event, at: new Date() });
};

@Inherit()
@Injectable("FOR_EVENT")
@Controller()
class MyLoginWorkflow extends LoginWorkflow {
  constructor(u: UserService, a: AuthCredential) {
    super(myLoginOpts, u, a);
  }
  protected override audit(e: AuditEvent) {
    return writeAudit(e);
  }
}

@Inherit()
@Injectable("FOR_EVENT")
@Controller()
class MyRecoveryWorkflow extends RecoveryWorkflow {
  constructor(u: UserService, a: AuthCredential) {
    super(myRecoveryOpts, u, a);
  }
  protected override audit(e: AuditEvent) {
    return writeAudit(e);
  }
}

@Inherit()
@Injectable("FOR_EVENT")
@Controller()
class MyInviteWorkflow extends InviteWorkflow {
  constructor(u: UserService, a: AuthCredential) {
    super(myInviteOpts, u, a);
  }
  protected override audit(e: AuditEvent) {
    return writeAudit(e);
  }
}
```

## Disabling audit per workflow

| Workflow           | Option                | Default | Notes                                                                            |
| ------------------ | --------------------- | ------- | -------------------------------------------------------------------------------- |
| `LoginWorkflow`    | `finalize.auditLogin` | `true`  | When `false`, the `audit-login` step is skipped entirely.                        |
| `RecoveryWorkflow` | `audit.enabled`       | `true`  | When `false`, both `recovery.requested` and `recovery.completed` are suppressed. |
| `InviteWorkflow`   | `audit.enabled`       | `true`  | When `false`, all four invite events are suppressed.                             |

Use these knobs when:

- Tests assert audit behaviour separately and the load-bearing assertion is "no audit when disabled".
- You wire audit at a different layer (e.g. an HTTP middleware that captures every request, including the workflow ones) and want to avoid double-recording.

## Standard fields and how they're populated

| Field       | Source                                                                        |
| ----------- | ----------------------------------------------------------------------------- |
| `userId`    | Workflow `ctx.username` (or `ctx.userId`) when resolved.                      |
| `workflow`  | The wfid (`auth.login`, `auth.recovery`, `auth.invite`).                      |
| `ip`        | `useRequest().rawRequest.socket.remoteAddress` at the originating HTTP event. |
| `userAgent` | `useHeaders().get('user-agent')` at the originating HTTP event.               |
| `kind`      | The event-specific discriminant.                                              |

For workflow events created via `WfTriggerProvider.handle()`, `ip` and `userAgent` are read from the **originating** HTTP event through Moost's `parent` chain — even when a step is paused for an outlet roundtrip and resumed minutes later, the IP and user-agent on the audit event are the resumption-request values (not the original click).

## Extending event types

`AuditEvent`'s index signature `[k: string]: unknown` makes it extensible. Add fields freely from inside an override:

```ts
protected override async audit(event: AuditEvent) {
  await writeAudit({
    ...event,
    requestId: useRequest().rawRequest.headers["x-request-id"],
    tenantId: useAuth().getAuthContext()?.claims?.tenantId,
  });
}
```

If you want compile-time typing for a custom shape, declaration-merge:

```ts
declare module "@aoothjs/auth-moost" {
  interface AuditEvent {
    requestId?: string;
    tenantId?: string;
  }
}
```

## See also

- [Workflows](./workflows) — full step phases for each workflow.
- [Config Reference](./config) — the workflow option tables that control `audit.enabled` / `finalize.auditLogin`.
