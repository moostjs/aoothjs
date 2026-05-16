/**
 * Sanity tests for the `AuditEmitter` interface contract + the shipped
 * `NoopAuditEmitter` default.
 *
 * The `LoginWorkflow.audit-login` step falls back to `NoopAuditEmitter` when no
 * consumer-supplied emitter is registered — this test pins that fallback as a
 * silent contract so a future refactor can't accidentally throw on missing-DI
 * and break logins.
 */
import { describe, expect, it } from "vite-plus/test";

import { type AuditEmitter, type AuditEvent, NoopAuditEmitter } from "../audit/index";

describe("NoopAuditEmitter", () => {
  it("emit() resolves without throwing for a typical login event", async () => {
    const ev: AuditEvent = {
      kind: "login.success",
      userId: "alice",
      workflow: "auth.login",
      method: "password",
    };
    // No assertion on return value — the contract is "does not throw".
    await NoopAuditEmitter.emit(ev);
  });

  it("emit() accepts events with no userId / workflow fields", async () => {
    await NoopAuditEmitter.emit({ kind: "anything.goes" });
  });

  it("is assignable to the AuditEmitter interface (compile-time contract)", () => {
    const e: AuditEmitter = NoopAuditEmitter;
    expect(typeof e.emit).toBe("function");
  });
});
