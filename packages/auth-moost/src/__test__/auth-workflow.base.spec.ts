import { UserAuthError } from "@aooth/user";
import { HttpError } from "@moostjs/event-http";
import { describe, expect, it } from "vite-plus/test";
import { ConsentStore } from "../consent.store";
import {
  AuthWorkflowBase,
  type InlineConsentCtx,
  type InlineConsentInput,
} from "../workflows/auth-workflow.base";

// `withStoreErrorTranslation` is `protected`; the test subclass exposes it so
// we can pin the OCC error→HTTP contract without standing up a full workflow.
// The same subclass also exposes `processInlineConsent` so the HACK-CONSENT
// security gates can be pinned without dragging in the full LoginWorkflow
// dispatch — these gates are workflow-agnostic by design (the helper takes a
// structural `InlineConsentCtx` and a `WfRequireInputOnly` interface).
//
// `consentStore` satisfies `AuthWorkflowBase`'s abstract getter (used by the
// inherited `persistConsentsStep` @Step). These tests don't exercise consent
// persistence, so a default no-op `ConsentStore` instance is sufficient.
// `consentsWorkflowId` satisfies the paired abstract getter used by the
// inherited `prepareConsents` @Step. These tests don't fire that step.
class ExposedBase extends AuthWorkflowBase {
  protected readonly consentStore: ConsentStore = new ConsentStore();
  protected get consentsWorkflowId(): string {
    return "auth/test/flow";
  }
  public run<T>(op: () => Promise<T>): Promise<T> {
    return this.withStoreErrorTranslation(op);
  }
  public consent(
    ctx: InlineConsentCtx,
    input: InlineConsentInput,
    wf: { requireInput(opts?: { errors?: Record<string, string>; formMessage?: string }): unknown },
  ): void {
    this.processInlineConsent(ctx, input, wf);
  }
}

/**
 * Minimal `wf` mock that captures the last `requireInput` call and returns a
 * sentinel Error the caller throws. Mirrors `useAtscriptWf(form).requireInput`
 * — the production code throws what `requireInput` returns; we throw a real
 * Error here so the catch sites match the same shape.
 */
function makeWf(): {
  requireInput: (opts?: { errors?: Record<string, string>; formMessage?: string }) => Error;
  lastCall?: { errors?: Record<string, string>; formMessage?: string };
} {
  const captured: {
    requireInput: (opts?: { errors?: Record<string, string>; formMessage?: string }) => Error;
    lastCall?: { errors?: Record<string, string>; formMessage?: string };
  } = {
    requireInput: (opts) => {
      captured.lastCall = opts;
      return new Error("requireInput");
    },
  };
  return captured;
}

describe("AuthWorkflowBase.withStoreErrorTranslation", () => {
  it("maps UserAuthError('CAS_EXHAUSTED') → HttpError(409) so OCC retry budget exhaustion surfaces as Conflict, not 500", async () => {
    // WHY: the wire-facing withCas-backed paths (addMfaMethod,
    // confirmMfaMethod, addTrustedDevice — plus verifyMfa for TOTP-replay
    // defense) can race under concurrent legitimate use.
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

// ── HACK-CONSENT — `processInlineConsent` security gates ───────────────────
//
// Phase 5 reshape: the helper consumes the dynamic `consents: string[]`
// field on the carrier form against the SERVER-OWNED `ctx.pendingConsents`
// whitelist (populated once by the `prepare-consents` @Step from
// `ConsentStore.getPendingConsents`). Key invariants pinned by the tests
// below:
//
//   1. SILENT-DROP — ids in `input.consents` that don't match a pending
//      descriptor are silently discarded. No error, no log, no signal back
//      to the client. Preserves the audit-grade
//      "what user saw is what server records" guarantee — an attacker
//      forging extra ids cannot pollute the audit trail.
//   2. MANDATORY-BY-MESSAGE — a descriptor with a non-empty `required`
//      string IS the per-row error copy. Submitting without that id in the
//      `consents` array trips a `requireInput({ errors: { consents:
//      <required-string> } })`.
//   3. IDEMPOTENT-ONCE — once `consentsPersisted` is true, the helper is a
//      no-op (a subsequent carrier-form submission cannot re-stage).
//   4. EMPTY-PENDING-NOOP — when there are no pending consents (default
//      `ConsentStore.getPendingConsents` returns `[]`), the helper short-
//      circuits before reading the input. The carrier form's
//      `AsConsentArray` self-hides on the same condition; the helper
//      mirrors that on the server.
describe("AuthWorkflowBase.processInlineConsent — security gates (HACK-CONSENT)", () => {
  it("HACK-CONSENT-01: consentsPersisted=true → submitted consents are SILENTLY IGNORED (no second stage)", () => {
    // WHY: idempotency invariant. Once a workflow run has persisted its
    // consent batch, a subsequent carrier-form submission cannot re-trigger
    // staging — that would fan a second `consentStore.save` call with the
    // same descriptors, polluting audit logs. The `if (ctx.consentsPersisted)
    // return` guard at the top of the helper closes this loop.
    const base = new ExposedBase();
    const ctx: InlineConsentCtx = {
      pendingConsents: [{ id: "terms", text: "Accept the Terms", required: "must accept" }],
      consentsPersisted: true,
    };
    const wf = makeWf();
    base.consent(ctx, { consents: ["terms"] }, wf);
    // Helper must NOT throw — defense is silent. State must NOT mutate (no
    // acceptedConsentIds, no consentsDecidedAt). The persisted flag must
    // stay true.
    expect(wf.lastCall).toBeUndefined();
    expect(ctx.acceptedConsentIds).toBeUndefined();
    expect(ctx.consentsDecidedAt).toBeUndefined();
    expect(ctx.consentsPersisted).toBe(true);
  });

  it("HACK-CONSENT-DECIDED-01: consentsDecidedAt already set → helper short-circuits (multi-carrier-form runs don't re-validate)", () => {
    // WHY: workflows with multiple carrier forms (e.g. login's AskEmailForm
    // → ProfileCompleteForm) each `extends WithInlineConsentForm` and pass
    // their input through `processInlineConsent`. Once the FIRST carrier
    // form captures the user's ticks (consentsDecidedAt set), subsequent
    // carrier forms MUST NOT re-run required-checks against their (empty,
    // because the user already ticked once) payload. The
    // `if (ctx.consentsDecidedAt !== undefined) return` guard closes this
    // loop. Without it, ProfileCompleteForm submission would throw the
    // descriptor's `required` string and the user would be stuck even
    // though they accepted on AskEmailForm earlier.
    const base = new ExposedBase();
    const ctx: InlineConsentCtx = {
      pendingConsents: [{ id: "terms", text: "Terms", required: "must accept" }],
      acceptedConsentIds: ["terms"],
      consentsDecidedAt: Date.now() - 1000, // captured a second ago on a prior form
    };
    const wf = makeWf();
    // Empty `consents` on the LATER carrier form — must NOT throw, must
    // NOT mutate state.
    base.consent(ctx, { consents: [] }, wf);
    expect(wf.lastCall).toBeUndefined();
    expect(ctx.acceptedConsentIds).toEqual(["terms"]);
  });

  it("HACK-CONSENT-02: empty pendingConsents → submitted consents IGNORED (cannot force-collect)", () => {
    // WHY: parallel anti-fabrication guarantee. With the dynamic-consent
    // shape, `pendingConsents` is the server's authoritative whitelist of
    // expected ids. An attacker submitting `consents: ['terms']` when the
    // server's pending list is empty MUST NOT cause the helper to stage
    // those ids — that would fake an acceptance record the policy never
    // asked for (GDPR / CASL liability surface). The `if (pending.length
    // === 0) return` short-circuit closes this loop.
    const base = new ExposedBase();
    // Case A: pendingConsents entirely undefined.
    const ctxA: InlineConsentCtx = {};
    const wfA = makeWf();
    base.consent(ctxA, { consents: ["terms"] }, wfA);
    expect(wfA.lastCall).toBeUndefined();
    expect(ctxA.acceptedConsentIds).toBeUndefined();
    expect(ctxA.consentsDecidedAt).toBeUndefined();
    // Case B: pendingConsents explicit empty array.
    const ctxB: InlineConsentCtx = { pendingConsents: [] };
    const wfB = makeWf();
    base.consent(ctxB, { consents: ["terms"] }, wfB);
    expect(wfB.lastCall).toBeUndefined();
    expect(ctxB.acceptedConsentIds).toBeUndefined();
    expect(ctxB.consentsDecidedAt).toBeUndefined();
  });

  it("HACK-CONSENT-03: silent-drop unknown ids — attacker cannot forge audit rows for never-displayed consents", () => {
    // WHY: load-bearing audit invariant. The server reads its own
    // `pendingConsents` as the whitelist; any id in `input.consents`
    // outside that set is silently dropped (NO error surfaced — surfacing
    // would leak the consent universe to a probing attacker). A regression
    // that propagated client-supplied ids straight through to
    // `acceptedConsentIds` would let an attacker submit
    // `consents: ['terms', 'gdpr-forged', 'phishy-extra']` and forge audit
    // records for consents they were never shown — breaking the
    // "what user saw is what server records" guarantee.
    const base = new ExposedBase();
    const ctx: InlineConsentCtx = {
      pendingConsents: [{ id: "terms", text: "Accept the Terms" }],
    };
    const wf = makeWf();
    base.consent(ctx, { consents: ["terms", "gdpr-forged", "phishy-extra"] }, wf);
    // No error surfaced — defense is silent (no signal back to the client).
    expect(wf.lastCall).toBeUndefined();
    // Only the valid id rides through; forged ids dropped on the floor.
    expect(ctx.acceptedConsentIds).toEqual(["terms"]);
  });

  it("HACK-CONSENT-04: missing required descriptor → requireInput throws with the descriptor's `required` STRING as error copy", () => {
    // WHY: the mandatory-by-message contract. A `required` non-empty
    // string IS the per-row error message (NOT just a boolean flag). A
    // regression that surfaced a generic "field required" string would
    // break the customer's per-consent UX contract — the whole point of
    // making `required` a string is to let customers define localized
    // copy. The first missing required descriptor wins the form-level
    // error.
    const base = new ExposedBase();
    const ctx: InlineConsentCtx = {
      pendingConsents: [
        {
          id: "terms",
          text: "Accept the Terms",
          required: "Privacy Policy acceptance is mandatory",
        },
      ],
    };
    const wf = makeWf();
    expect(() => base.consent(ctx, { consents: [] }, wf)).toThrow();
    expect(wf.lastCall?.errors).toMatchObject({
      consents: "Privacy Policy acceptance is mandatory",
    });
    // State must NOT mutate on the throw path.
    expect(ctx.acceptedConsentIds).toBeUndefined();
    expect(ctx.consentsDecidedAt).toBeUndefined();
  });

  it("HACK-CONSENT-05: required with empty input.consents undefined → same throw as empty array (treats missing as empty)", () => {
    // WHY: an attacker omitting the `consents` field entirely on a hand-
    // rolled POST MUST behave identically to submitting `[]` — the
    // mandatory check fires either way. The `input.consents ?? []` fall-
    // back at the top of the helper closes this loop. Without it, an
    // omitted field would slip past the iteration over `pending` and
    // silently accept the workflow with no recorded acceptance.
    const base = new ExposedBase();
    const ctx: InlineConsentCtx = {
      pendingConsents: [{ id: "terms", text: "Accept Terms", required: "must accept" }],
    };
    const wf = makeWf();
    expect(() => base.consent(ctx, {}, wf)).toThrow();
    expect(wf.lastCall?.errors?.consents).toBe("must accept");
  });

  it("HACK-CONSENT-06: optional descriptor with empty `required` ⇒ unsubmitted is OK (no throw, no stage of that id)", () => {
    // WHY: explicit-empty-string `required` MUST be treated as optional
    // (NOT as "mandatory with empty error copy"). The helper's truthy
    // check `if (p.required && !submitted.has(p.id))` uses string
    // truthiness so `''` and `undefined` both collapse to "optional".
    // A regression that flipped to `p.required !== undefined` would
    // silently make every empty-string descriptor mandatory.
    const base = new ExposedBase();
    const ctx: InlineConsentCtx = {
      pendingConsents: [
        { id: "marketing", text: "Marketing", required: "" },
        { id: "research", text: "Research", required: undefined },
      ],
    };
    const wf = makeWf();
    // Submit nothing — both descriptors are optional.
    base.consent(ctx, { consents: [] }, wf);
    expect(wf.lastCall).toBeUndefined();
    expect(ctx.acceptedConsentIds).toEqual([]);
    expect(typeof ctx.consentsDecidedAt).toBe("number");
  });

  it("happy path: all required satisfied, optional ticked → acceptedConsentIds reflects the validated subset; consentsDecidedAt stamped", () => {
    // WHY: positive control alongside the HACK-CONSENT-* negatives.
    // Without this, a refactor that closes the gates unconditionally
    // (over-defending) would pass every HACK-CONSENT test while breaking
    // the legitimate path. The accepted subset MUST match what the user
    // ticked, intersected with the server-owned whitelist.
    const base = new ExposedBase();
    const ctx: InlineConsentCtx = {
      pendingConsents: [
        { id: "terms", text: "Terms", required: "Required" },
        { id: "marketing", text: "Marketing" },
        { id: "research", text: "Research" },
      ],
    };
    const wf = makeWf();
    base.consent(ctx, { consents: ["terms", "research"] }, wf);
    expect(wf.lastCall).toBeUndefined();
    expect(ctx.acceptedConsentIds).toEqual(["terms", "research"]);
    // Timestamp captured at acceptance moment (the load-bearing "user-
    // action time" semantic — survives paused-workflow resume gaps).
    expect(typeof ctx.consentsDecidedAt).toBe("number");
  });

  it("consentsDecidedAt captured at helper-run time (not at persist-step time)", () => {
    // WHY (Rule 9): the batched `consentStore.save(username, events)`
    // receives `at` per event — the WHY of that field is "when the user
    // actually clicked submit", which must survive a paused-workflow
    // resume gap. If the helper deferred the timestamp to the persist
    // step (or didn't capture it at all), the recorded `at` could drift
    // hours away from the user-action moment for a paused workflow that
    // resumes later. Bound to wall-clock ms around `Date.now()` (not
    // exact equality — we're verifying the INTENT, not the WHAT).
    const base = new ExposedBase();
    const ctx: InlineConsentCtx = {
      pendingConsents: [{ id: "terms", text: "Terms" }],
    };
    const wf = makeWf();
    const before = Date.now();
    base.consent(ctx, { consents: ["terms"] }, wf);
    const after = Date.now();
    expect(ctx.consentsDecidedAt).toBeGreaterThanOrEqual(before);
    expect(ctx.consentsDecidedAt).toBeLessThanOrEqual(after);
  });
});
