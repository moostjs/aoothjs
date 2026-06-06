import type { AuthSmsEvent, SmsSender } from "@aooth/auth";

/**
 * Console `SmsSender` for the demo — the SMS counterpart to
 * {@link ConsoleEmailSender}. `@aooth/auth` ships only the `SmsSender`
 * interface (Twilio / SNS are consumer-specific), so the demo supplies this
 * concrete dev/test logger. In `DEMO_MODE=test` the app captures events into a
 * shared buffer instead (see `app.ts`); this logger is the non-test fallback.
 */
export class ConsoleSmsSender implements SmsSender {
  send(event: AuthSmsEvent): Promise<void> {
    const parts = [
      "[SMS]",
      `kind=${event.kind}`,
      `to=${event.recipient}`,
      `code=${event.code}`,
      `ttlMs=${event.ttlMs}`,
    ].join(" ");
    // biome-ignore lint/suspicious/noConsole: demo logger
    console.log(parts);
    return Promise.resolve();
  }
}
