# Audit Log

`@aooth/auth-moost` exports two audit **types** but ships **no audit sink, and the bundled `AuthWorkflow` does not emit audit events itself.** There is no `audit()` hook on the workflow. This page documents the types and how to wire your own auditing.

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

`AuditEvent`'s open index signature lets you carry any extra fields; `AuditEmitter` is a minimal sink contract. Both are exported so your code and a shared audit utility can speak the same shape — neither is wired into the workflow for you.

## Wiring your own auditing

Two practical placements:

### 1. From an `AuthWorkflow` subclass step

Emit from inside a `@Step` body (or an overridden `resolveXxx` / `deliver`) where you have the relevant context. For example, record a successful login by overriding the finalize step in your subclass and calling your own emitter:

```ts
import { AuthCredential } from "@aooth/auth";
import {
  type AuditEvent,
  type AuthDeliveryPayload,
  AuthWorkflow,
  ConsentStore,
} from "@aooth/auth-moost";
import { UserService } from "@aooth/user";
import { Controller, Inherit } from "moost";

const writeAudit = (e: AuditEvent) => auditTable.insert({ ...e, at: Date.now() });

@Inherit()
@Controller()
class MyAuth extends AuthWorkflow {
  constructor(users: UserService, auth: AuthCredential, consents: ConsentStore) {
    super({}, users, auth, consents);
  }
  // override a step or hook method and emit your event
  protected override async deliver(payload: AuthDeliveryPayload): Promise<void> {
    await writeAudit({ kind: `deliver.${payload.kind}`, workflow: "auth", ...this.eventMeta() });
    await super.deliver(payload);
  }
  private eventMeta(): Pick<AuditEvent, "ip" | "userAgent"> {
    // the client IP the HTTP app resolves (its `trustProxy`) and the User-Agent header
    return { ip: this.resolveClientIp(), userAgent: this.resolveUserAgent() };
  }
}
```

### 2. From a global interceptor

For uniform request-level auditing across **all** routes (not just auth), a `defineAfterInterceptor` that records every event is usually the better seam — it captures HTTP requests and workflow steps alike, and avoids per-step override boilerplate. Workflow events inherit the originating HTTP event's `AuthContext`, IP, and user-agent through Moost's `parent` chain, so an interceptor reads the same values a step would.

## Populating the standard fields

| Field       | Source                                                                                                                                                                                                                                                           |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `userId`    | `useAuth().getAuthContext()?.userId` (or the workflow's `ctx.subject`).                                                                                                                                                                                          |
| `workflow`  | The wfid (`auth/login/flow`, `auth/invite/start`, `auth/recovery/flow`, `auth/signup/flow`, `auth/change-password/flow`).                                                                                                                                        |
| `ip`        | `useRequest().getIp()` at the originating HTTP event — in an `AuthWorkflow` subclass `this.resolveClientIp()`. It is the client IP the HTTP app resolves, so it follows the app's `trustProxy` (behind a proxy, set it — otherwise this is the proxy's address). |
| `userAgent` | `useHeaders()["user-agent"]` at the originating HTTP event (a plain header object) — in an `AuthWorkflow` subclass `this.resolveUserAgent()`.                                                                                                                    |
| `kind`      | Your event-specific discriminant.                                                                                                                                                                                                                                |

## Extending the event shape

The `[k: string]: unknown` index signature makes `AuditEvent` extensible at runtime. For compile-time typing of a custom shape, declaration-merge:

```ts
declare module "@aooth/auth-moost" {
  interface AuditEvent {
    requestId?: string;
    tenantId?: string;
  }
}
```

## See also

- [Workflows](./workflows) — the override seams (`deliver`, `resolveXxx`, `@Step`) you emit from.
- [API reference](/api/auth-moost#audit-types) — the exported `AuditEvent` / `AuditEmitter` signatures.
