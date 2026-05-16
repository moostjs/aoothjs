import type { AuthEmailEvent, EmailSender } from "@aoothjs/auth";

export class ConsoleEmailSender implements EmailSender {
  send(event: AuthEmailEvent): Promise<void> {
    const parts = [
      "[EMAIL]",
      `kind=${event.kind}`,
      `to=${event.recipient}`,
      event.url ? `url=${event.url}` : "",
      event.code ? `code=${event.code}` : "",
      `expires=${new Date(event.expiresAt).toISOString()}`,
    ]
      .filter(Boolean)
      .join(" ");
    // biome-ignore lint/suspicious/noConsole: demo logger
    console.log(parts);
    if (event.metadata) {
      // biome-ignore lint/suspicious/noConsole: demo logger
      console.log(`  metadata: ${JSON.stringify(event.metadata)}`);
    }
    return Promise.resolve();
  }
}
