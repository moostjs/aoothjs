import { UserAuthError } from "@aooth/user";
import { HttpError } from "@moostjs/event-http";
import { describe, expect, it } from "vite-plus/test";
import { AuthWorkflowBase } from "../workflows/auth-workflow.base";

// `withStoreErrorTranslation` is `protected`; the test subclass exposes it so
// we can pin the OCC error→HTTP contract without standing up a full workflow.
class ExposedBase extends AuthWorkflowBase {
  public run<T>(op: () => Promise<T>): Promise<T> {
    return this.withStoreErrorTranslation(op);
  }
}

describe("AuthWorkflowBase.withStoreErrorTranslation", () => {
  it("maps UserAuthError('CAS_EXHAUSTED') → HttpError(409) so OCC retry budget exhaustion surfaces as Conflict, not 500", async () => {
    // WHY: the four wire-facing withCas-backed paths (consumeBackupCode,
    // addMfaMethod, confirmMfaMethod, addTrustedDevice — plus verifyMfa for
    // TOTP-replay defense) can race under concurrent legitimate use.
    // Without this translation a CAS-exhausted retry would bubble to moost's
    // default 500, falsely signalling a broken server — clients SHOULD retry
    // on 409.
    const base = new ExposedBase();
    const caught = await base
      .run(async () => {
        throw new UserAuthError("CAS_EXHAUSTED");
      })
      .catch((e: unknown) => e);
    expect(caught).toBeInstanceOf(HttpError);
    expect((caught as HttpError).body.statusCode).toBe(409);
  });

  it("passes through non-CAS UserAuthError unchanged so step-local catch blocks still see them", async () => {
    // WHY: existing handlers (e.g. login workflow's TOTP branch catches
    // MFA_INVALID to re-prompt the form, invite catches ALREADY_EXISTS to
    // raise 409 with a different reason) MUST still receive the raw
    // UserAuthError. Translation must be narrow.
    const base = new ExposedBase();
    const original = new UserAuthError("MFA_INVALID");
    await expect(
      base.run(async () => {
        throw original;
      }),
    ).rejects.toBe(original);
  });

  it("returns the operation's value when no error is thrown", async () => {
    const base = new ExposedBase();
    await expect(base.run(async () => 42)).resolves.toBe(42);
  });

  it("rethrows non-UserAuthError unchanged (programmer bugs / framework errors aren't OCC failures)", async () => {
    const base = new ExposedBase();
    const boom = new Error("kaboom");
    await expect(
      base.run(async () => {
        throw boom;
      }),
    ).rejects.toBe(boom);
  });
});
