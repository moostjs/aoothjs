# Email & SMS Senders

`@aooth/auth` ships **interfaces only** for email and SMS delivery. There's no SES, no SendGrid, no Twilio adapter inside the package — you bring the implementation, the workflow calls it through these contracts.

This page covers the two contracts, their event shapes, the kind unions, and worked implementations against SES (email) and Twilio (SMS).

## The contracts

```ts
interface EmailSender {
  send(event: AuthEmailEvent): Promise<void>;
}

interface SmsSender {
  send(event: AuthSmsEvent): Promise<void>;
}
```

Both return `Promise<void>`. Workflows **`await`** the call — it's part of the request path. See the [warning below](#await-and-blocking-transports) on blocking transports.

## Email

### `AuthEmailKind`

| Kind                   | Meaning                                            | Carries                          |
| ---------------------- | -------------------------------------------------- | -------------------------------- |
| `'recovery.magicLink'` | Password recovery — click-through reset link       | `url`, `expiresAt`, `username?`  |
| `'invite.magicLink'`   | Account invitation — click-through onboarding link | `url`, `expiresAt`, `username?`  |
| `'mfa.code'`           | Step-up MFA challenge code                         | `code`, `expiresAt`, `username?` |
| `'login.pincode'`      | Login via pincode (email-OTP)                      | `code`, `expiresAt`, `username?` |
| `'recovery.pincode'`   | Recovery via pincode                               | `code`, `expiresAt`, `username?` |
| `'invite.pincode'`     | Invitation via pincode                             | `code`, `expiresAt`, `username?` |
| `'notifyNewDevice'`    | Informational — new device logged in               | `metadata` only                  |

The kind is also what `BuildMagicLinkUrl(kind, token, ctx?)` receives — so a single `EmailSender` can multiplex over templates by kind.

### `AuthEmailEvent`

```ts
interface AuthEmailEvent {
  kind: AuthEmailKind;
  recipient: string;
  url?: string;
  code?: string;
  expiresAt: number; // ms since epoch
  username?: string;
  metadata?: Record<string, unknown>;
}
```

`metadata` is intentionally a free-form `Record<string, unknown>` — workflows push notify-side ip / user-agent, invite-side `roles: string[]`, locale hints, etc. It is **not** the per-credential `CredentialMetadata` shape.

| Field       | Always present          | Notes                                                         |
| ----------- | ----------------------- | ------------------------------------------------------------- |
| `kind`      | yes                     | Discriminator. Use it to route to the right template.         |
| `recipient` | yes                     | Email address. The package never validates the format.        |
| `url`       | for magic-link kinds    | Pre-built by `BuildMagicLinkUrl`.                             |
| `code`      | for pincode / MFA kinds | Plain string — the workflow generates and stores.             |
| `expiresAt` | yes                     | Absolute ms timestamp. Render as a relative duration.         |
| `username`  | when known              | Display name / email — workflows pass it for personalisation. |
| `metadata`  | for `'notifyNewDevice'` | IP / UA / fingerprint / label of the new session.             |

::: tip One sender, many templates
`EmailSender` is a single method. Branch on `event.kind` inside the implementation to pick a template, subject line, and locale. Keep one sender per provider, not one per kind.
:::

### Implementing `EmailSender` (SES)

```ts
import type { EmailSender, AuthEmailEvent, AuthEmailKind } from "@aooth/auth";
import { SESClient, SendEmailCommand } from "@aws-sdk/client-ses";

interface EmailTemplate {
  subject: string;
  html: (event: AuthEmailEvent) => string;
}

const templates: Record<AuthEmailKind, EmailTemplate> = {
  "recovery.magicLink": {
    subject: "Reset your password",
    html: (e) => `
      <p>Hi ${e.username ?? "there"},</p>
      <p>Click below to reset your password. The link expires at ${new Date(e.expiresAt).toUTCString()}.</p>
      <p><a href="${e.url}">Reset password</a></p>
    `,
  },
  "invite.magicLink": {
    subject: "You've been invited",
    html: (e) =>
      `<p><a href="${e.url}">Accept the invite</a> by ${new Date(e.expiresAt).toUTCString()}.</p>`,
  },
  "mfa.code": {
    subject: "Your verification code",
    html: (e) => `<p>Your code: <strong>${e.code}</strong></p>`,
  },
  // … one entry per kind
  "login.pincode": { subject: "Sign-in code", html: (e) => `<p>Your code: ${e.code}</p>` },
  "recovery.pincode": { subject: "Recovery code", html: (e) => `<p>Your code: ${e.code}</p>` },
  "invite.pincode": { subject: "Invitation code", html: (e) => `<p>Your code: ${e.code}</p>` },
  notifyNewDevice: {
    subject: "New sign-in",
    html: (e) => `<p>New sign-in from ${e.metadata?.ip ?? "?"}.</p>`,
  },
};

export class SesEmailSender implements EmailSender {
  constructor(
    private readonly ses: SESClient,
    private readonly from: string,
  ) {}

  async send(event: AuthEmailEvent): Promise<void> {
    const tpl = templates[event.kind];
    await this.ses.send(
      new SendEmailCommand({
        Source: this.from,
        Destination: { ToAddresses: [event.recipient] },
        Message: {
          Subject: { Data: tpl.subject, Charset: "UTF-8" },
          Body: { Html: { Data: tpl.html(event), Charset: "UTF-8" } },
        },
      }),
    );
  }
}
```

Wire it once at startup, hand it to the workflow:

```ts
const emailSender = new SesEmailSender(
  new SESClient({ region: "eu-west-1" }),
  "noreply@example.com",
);
```

### A SendGrid variant

```ts
import sgMail from "@sendgrid/mail";
import type { EmailSender, AuthEmailEvent } from "@aooth/auth";

sgMail.setApiKey(process.env.SENDGRID_API_KEY!);

export class SendgridEmailSender implements EmailSender {
  async send(e: AuthEmailEvent): Promise<void> {
    await sgMail.send({
      to: e.recipient,
      from: "noreply@example.com",
      templateId: templateIdFor(e.kind),
      dynamicTemplateData: {
        url: e.url,
        code: e.code,
        expiresAt: e.expiresAt,
        username: e.username,
      },
    });
  }
}

function templateIdFor(kind: AuthEmailEvent["kind"]): string {
  // map kind → SendGrid dynamic template id
  return /* … */ "";
}
```

## SMS

### `AuthSmsKind`

| Kind                 | Meaning                |
| -------------------- | ---------------------- |
| `'login.pincode'`    | Sign-in via SMS-OTP    |
| `'recovery.pincode'` | Recovery via SMS-OTP   |
| `'invite.pincode'`   | Invitation via SMS-OTP |

SMS is **pincode-only**. There are no magic-link SMS kinds in the package — SMS deliverability is unreliable enough that a one-shot 6-digit code is the only practical primitive.

### `AuthSmsEvent`

```ts
interface AuthSmsEvent {
  kind: AuthSmsKind;
  recipient: string; // E.164, e.g. "+351912345678"
  code: string;
  ttlMs: number;
  userId?: string;
}
```

| Field       | Notes                                                                          |
| ----------- | ------------------------------------------------------------------------------ |
| `kind`      | One of the three kinds above.                                                  |
| `recipient` | E.164 phone number. The package never validates the format.                    |
| `code`      | Plain pincode — the workflow generates and stores it.                          |
| `ttlMs`     | Pincode lifetime in milliseconds. Render as a relative duration.               |
| `userId`    | Available when the recipient already has an account; absent during invitation. |

### Implementing `SmsSender` (Twilio)

```ts
import type { SmsSender, AuthSmsEvent } from "@aooth/auth";
import twilio from "twilio";

export class TwilioSmsSender implements SmsSender {
  private readonly client: ReturnType<typeof twilio>;
  constructor(
    accountSid: string,
    authToken: string,
    private readonly from: string,
  ) {
    this.client = twilio(accountSid, authToken);
  }

  async send(event: AuthSmsEvent): Promise<void> {
    const minutes = Math.max(1, Math.round(event.ttlMs / 60_000));
    const body = `Your code: ${event.code} (valid ${minutes} min)`;
    await this.client.messages.create({
      to: event.recipient,
      from: this.from,
      body,
    });
  }
}
```

### A different provider

```ts
import type { SmsSender, AuthSmsEvent } from "@aooth/auth";
import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";

export class SnsSmsSender implements SmsSender {
  constructor(private readonly sns: SNSClient) {}
  async send(event: AuthSmsEvent): Promise<void> {
    await this.sns.send(
      new PublishCommand({
        PhoneNumber: event.recipient,
        Message: `Your code: ${event.code}`,
      }),
    );
  }
}
```

## `await` and blocking transports

`workflow.send` calls `await emailSender.send(...)`. The workflow blocks until the promise resolves. This is intentional — a failed delivery should propagate as an HTTP 5xx, not silently disappear into a queue.

::: warning Don't block the request on a slow provider
A request waiting for a third-party HTTP roundtrip is fragile. Best practice: the sender pushes onto an internal queue (SQS, Redis Streams, BullMQ) and returns. A worker process consumes the queue and calls the real provider. The user-visible latency is the queue insert, which is sub-millisecond. The workflow still gets a `Promise<void>` it can `await`, but the resolution is bounded.

```ts
import type { EmailSender, AuthEmailEvent } from "@aooth/auth";

export class QueuedEmailSender implements EmailSender {
  constructor(private readonly queue: { add(j: unknown): Promise<void> }) {}
  async send(event: AuthEmailEvent): Promise<void> {
    await this.queue.add({ kind: "email", event });
    // returns when the job is on the queue, not when the email is delivered
  }
}
```

The trade-off: a delivery failure no longer surfaces to the request. Build a dead-letter queue and monitor it.
:::

## Registration with workflows

`@aooth/auth-moost` does **not** ship `EmailSender` / `SmsSender` as DI tokens — the unified `AuthWorkflow` routes direct sends through a single `protected deliver(payload: AuthDeliveryPayload)` override (branch on `payload.kind` + `payload.channel`). Senders are wired by closure into that override on your `AuthWorkflow` subclass.

The magic-link outlet (`createAuthEmailOutlet`) is the one place that takes an `EmailSender` directly — as a constructor dep on `WfTriggerProvider`, not via DI. Its `buildMagicLinkUrl` is the 3-arg `BuildMagicLinkUrl`:

```ts
import { createAuthEmailOutlet } from "@aooth/auth-moost";

const emailSender = new SesEmailSender(/* … */);

const outlet = createAuthEmailOutlet({
  emailSender,
  buildMagicLinkUrl: (kind, token, ctx) =>
    `https://app.example.com/wf/${kind}?wfs=${token}${ctx?.userId ? `&uid=${ctx.userId}` : ""}`,
  magicLinkTtlMs: (kind) => (kind === "invite.magicLink" ? 7 * 24 * 60 * 60_000 : 60 * 60_000),
});
```

Register the workflow itself via the replace registry and `registerControllers`:

```ts
import { createReplaceRegistry } from "moost";
import { AuthWorkflow } from "@aooth/auth-moost";

app.setReplaceRegistry(createReplaceRegistry([AuthWorkflow, MyAuth]));
app.registerControllers(AuthController, MyAuth);
```

Your `MyAuth extends AuthWorkflow` `deliver()` override holds the `EmailSender` / `SmsSender` in closure and routes by `payload.channel`. See [Moost — Workflows](../moost/workflows).

## Locales and templates

The package ships no locale machinery. Branch inside your sender:

```ts
async send(event: AuthEmailEvent): Promise<void> {
  const locale = event.metadata?.label?.startsWith('locale=')
    ? event.metadata.label.slice(7)
    : 'en';
  const tpl = templates[locale][event.kind];
  /* … */
}
```

A common pattern: stash the locale in `metadata.label` at issue-time and read it back in the sender.

## See also

- [Magic Links](./magic-links) — `BuildMagicLinkUrl` and how `url` ends up on the event.
- [Password Reset](./password-reset) — the workflow shape that emits `'recovery.magicLink'`.
- [Moost — Workflows](../moost/workflows) — how senders are wired into DI.
- Source: [packages/auth/src/transport.ts](https://github.com/moostjs/aoothjs/blob/main/packages/auth/src/transport.ts).
