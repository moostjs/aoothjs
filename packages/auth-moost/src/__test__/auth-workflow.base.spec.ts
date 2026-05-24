import { UserAuthError } from "@aooth/user";
import { HttpError } from "@moostjs/event-http";
import { describe, expect, it } from "vite-plus/test";
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
class ExposedBase extends AuthWorkflowBase {
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

// ── HACK-CONSENT — `processInlineConsent` security gates ───────────────────
//
// SECURITY: inline consent fields ride alongside legitimate carrier-form
// data (`acceptedTerms`, `marketingOptIn` on `LoginCredentialsForm` /
// `SetPasswordForm` / `AskEmailForm` / `AskPhoneForm` /
// `ProfileCompleteForm`). The `@ui.form.fn.hidden` expression only governs
// CLIENT visibility — a malicious client can always POST whatever values it
// wants. The server-side guarantee lives in
// `AuthWorkflowBase.processInlineConsent`: gates close (a) once consent has
// already been captured this run, AND (b) when the acceptance policy says
// the field is not collected for this user. Each test below pins one of
// those gates by asserting that the SAME submitted payload either takes
// effect (gate open) or is silently dropped (gate closed) depending on the
// surrounding ctx state. A regression that flips a gate's polarity would
// either over-collect (consent fabricated when policy is off) or
// under-collect (legitimate updates silently dropped); both fail loudly here.
//
// Terms version is NOT a client-submitted field — the server writes
// `ctx.termsAcceptedVersion` from its own `ctx.acceptance.termsVersion`.
// HACK-CONSENT-03 pins THAT contract: even if a malicious client smuggles
// an `acceptedTermsVersion` field into the payload, the helper ignores it
// and records the server's version.
describe("AuthWorkflowBase.processInlineConsent — security gates (HACK-CONSENT)", () => {
  it("HACK-CONSENT-01: termsAcceptedDone=true → submitted acceptedTerms:false is SILENTLY IGNORED (cannot withdraw)", () => {
    // WHY: load-bearing anti-tamper guarantee. Once a user has accepted the
    // current terms version, no subsequent payload — legitimate or crafted —
    // can flip `termsAcceptedDone` back to false or rewrite
    // `termsAcceptedVersion`. The `if (… && !ctx.termsAcceptedDone)` guard at
    // auth-workflow.base.ts:291 is what closes this loop; removing that
    // condition lets an attacker post `{ acceptedTerms: false }` on any
    // later carrier form (e.g. a `ProfileCompleteForm` rendered AFTER terms
    // were captured on `LoginCredentialsForm`) and roll the user's
    // acceptance back. Server records would diverge from legal reality.
    const base = new ExposedBase();
    const ctx: InlineConsentCtx = {
      acceptance: { termsVersion: "v1", consentMarketing: false },
      termsAcceptedDone: true,
      termsAcceptedVersion: "v1",
    };
    const wf = makeWf();
    // Attacker resubmits the carrier-form payload with falsified consent.
    base.consent(ctx, { acceptedTerms: false }, wf);
    // Helper must NOT throw (no requireInput call) AND must NOT mutate the
    // already-captured state. The defense is silent — the falsified value
    // is dropped on the floor, not flagged. (Flagging would let probers
    // detect the user's acceptance state.)
    expect(wf.lastCall).toBeUndefined();
    expect(ctx.termsAcceptedDone).toBe(true);
    expect(ctx.termsAcceptedVersion).toBe("v1");
  });

  it("HACK-CONSENT-02: consentApplied=true → submitted marketingOptIn:false is SILENTLY IGNORED (no second write)", () => {
    // WHY: mirror anti-tamper guarantee for marketing opt-in. Once the
    // `apply-consent` step has persisted the user's choice (consentApplied
    // = true), no subsequent payload can re-stage `pendingMarketingOptIn`
    // and trigger a second write. The `if (… && !ctx.consentApplied …)`
    // guard at auth-workflow.base.ts:303-306 closes the loop. Without it,
    // an attacker who flips a user's opt-in by posting a new
    // `marketingOptIn:false` on any later carrier form would trigger a
    // second `applyConsentMarketing(username, false)` call — silently
    // toggling the user's preference against their wishes. Distinct from
    // HACK-CONSENT-01 because marketing has a separate apply-step gate.
    // No `termsVersion` here — isolates the marketing gate from the terms
    // gate so the test focuses on the consentApplied branch alone.
    const base = new ExposedBase();
    const ctx: InlineConsentCtx = {
      acceptance: { consentMarketing: true },
      consentApplied: true,
    };
    const wf = makeWf();
    base.consent(ctx, { marketingOptIn: false }, wf);
    expect(wf.lastCall).toBeUndefined();
    // The key load-bearing assertion — `pendingMarketingOptIn` MUST stay
    // undefined so the `apply-consent` step (gated on
    // `pendingMarketingOptIn !== undefined`) doesn't fire a second time.
    expect(ctx.pendingMarketingOptIn).toBeUndefined();
    expect(ctx.consentApplied).toBe(true);
  });

  it("HACK-CONSENT-03: server is authoritative for terms version — client cannot smuggle a fabricated version into ctx", () => {
    // WHY: the accepted version is NOT a client-submitted field — the
    // server writes `ctx.termsAcceptedVersion = ctx.acceptance.termsVersion`
    // directly. An attacker who smuggles `acceptedTermsVersion: "v999"`
    // into the payload (a non-typed extra field — `InlineConsentInput`
    // doesn't declare one, but the wire is JSON) MUST NOT cause the helper
    // to record the smuggled version. Asserting that ctx ends up with the
    // server's `acceptance.termsVersion` value pins the
    // `ctx.termsAcceptedVersion = ctx.acceptance.termsVersion` write at
    // auth-workflow.base.ts (the line that REPLACED the prior client-echo
    // assignment). A refactor that re-introduced `ctx.termsAcceptedVersion
    // = input.acceptedTermsVersion` would silently let attackers backdate
    // acceptance to a stale version that may have looser terms.
    const base = new ExposedBase();
    const ctx: InlineConsentCtx = {
      acceptance: { termsVersion: "v2", consentMarketing: false },
      termsAcceptedDone: false,
    };
    const wf = makeWf();
    // Cast through `unknown` because `InlineConsentInput` no longer
    // declares `acceptedTermsVersion` — this matches the wire reality
    // (untyped JSON body) and exercises the "extra fields are ignored"
    // contract.
    base.consent(
      ctx,
      { acceptedTerms: true, acceptedTermsVersion: "v999" } as unknown as InlineConsentInput,
      wf,
    );
    expect(wf.lastCall).toBeUndefined();
    expect(ctx.termsAcceptedDone).toBe(true);
    // Load-bearing: ctx records the SERVER'S version, NOT the smuggled value.
    expect(ctx.termsAcceptedVersion).toBe("v2");
  });

  it("HACK-CONSENT-04: acceptedTerms missing/false when policy active → requireInput with 'You must accept' error", () => {
    // WHY: the first-line gate. Without it, an attacker posting
    // `acceptedTerms: undefined` (or omitting the field entirely) on a
    // carrier form would slip past the inline check and reach the user
    // store with no acceptance recorded — defeating the entire purpose of
    // `acceptance.termsVersion`. The `if (!input.acceptedTerms)` guard at
    // auth-workflow.base.ts:292 is what catches both `false` and absent.
    const base = new ExposedBase();
    const ctx: InlineConsentCtx = {
      acceptance: { termsVersion: "v1", consentMarketing: false },
      termsAcceptedDone: false,
    };
    const wf = makeWf();
    // Absent acceptedTerms — same path as `acceptedTerms: false`.
    expect(() => base.consent(ctx, {}, wf)).toThrow();
    expect(wf.lastCall?.errors).toMatchObject({
      acceptedTerms: "You must accept the terms",
    });
    expect(ctx.termsAcceptedDone).toBeFalsy();
  });

  it("HACK-CONSENT-05: marketing field IGNORED when consentMarketing policy is off (cannot force-collect)", () => {
    // WHY: closes the inverse of HACK-CONSENT-02. If a consumer's policy
    // says `consentMarketing: false` (no marketing collection), a malicious
    // client posting `marketingOptIn: true` MUST NOT cause the workflow to
    // stage a `pendingMarketingOptIn` — that would then fire the
    // `apply-consent` step and write a marketing record the server's
    // policy never asked for (potential GDPR / CASL liability). The
    // `if (ctx.acceptance?.consentMarketing && …)` guard at
    // auth-workflow.base.ts:303 closes this loop.
    const base = new ExposedBase();
    const ctx: InlineConsentCtx = {
      acceptance: { consentMarketing: false }, // policy OFF — server doesn't collect marketing
    };
    const wf = makeWf();
    base.consent(ctx, { marketingOptIn: true }, wf);
    expect(wf.lastCall).toBeUndefined();
    // Critical: `pendingMarketingOptIn` MUST stay undefined so the
    // `apply-consent` step (gated on its presence) never fires.
    expect(ctx.pendingMarketingOptIn).toBeUndefined();
  });

  it("HACK-CONSENT-06: terms fields IGNORED when termsVersion policy is unset (cannot force-collect)", () => {
    // WHY: parallel anti-fabrication guarantee for terms. If `acceptance`
    // is undefined OR `termsVersion` is unset, an attacker submitting
    // `acceptedTerms: true` MUST NOT cause the helper to record an
    // acceptance — that would create a fake acceptance record the
    // server's policy doesn't actually require. The
    // `if (ctx.acceptance?.termsVersion && …)` guard at
    // auth-workflow.base.ts:291 closes this loop. Tested with `acceptance`
    // explicitly undefined to also exercise the optional-chaining short-
    // circuit (both branches collapse to "no acceptance, no write").
    const base = new ExposedBase();
    // Case A: acceptance entirely undefined.
    const ctxA: InlineConsentCtx = {};
    const wfA = makeWf();
    base.consent(ctxA, { acceptedTerms: true }, wfA);
    expect(wfA.lastCall).toBeUndefined();
    expect(ctxA.termsAcceptedDone).toBeUndefined();
    expect(ctxA.termsAcceptedVersion).toBeUndefined();
    // Case B: acceptance present but termsVersion unset.
    const ctxB: InlineConsentCtx = { acceptance: { consentMarketing: false } };
    const wfB = makeWf();
    base.consent(ctxB, { acceptedTerms: true }, wfB);
    expect(wfB.lastCall).toBeUndefined();
    expect(ctxB.termsAcceptedDone).toBeUndefined();
    expect(ctxB.termsAcceptedVersion).toBeUndefined();
  });

  it("happy path: opens both gates → terms captured + marketing staged for apply-consent", () => {
    // WHY: positive control alongside the HACK-CONSENT-* negatives. Pins
    // that when the gates are OPEN — policy on, not yet captured — the
    // helper writes both `termsAcceptedDone/Version` and stages
    // `pendingMarketingOptIn`. Without this positive control a refactor
    // that closes the gates unconditionally (over-defending) would pass
    // every HACK-CONSENT test while breaking the legitimate path.
    const base = new ExposedBase();
    const ctx: InlineConsentCtx = {
      acceptance: { termsVersion: "v1", consentMarketing: true },
    };
    const wf = makeWf();
    base.consent(ctx, { acceptedTerms: true, marketingOptIn: true }, wf);
    expect(wf.lastCall).toBeUndefined();
    expect(ctx.termsAcceptedDone).toBe(true);
    // Version is written by the server from `ctx.acceptance.termsVersion`,
    // not echoed from the client.
    expect(ctx.termsAcceptedVersion).toBe("v1");
    expect(ctx.pendingMarketingOptIn).toBe(true);
  });

  it("marketing opt-OUT (false) is a distinct, recordable value — NOT collapsed to undefined", () => {
    // WHY: pins the `input.marketingOptIn !== undefined` guard at
    // auth-workflow.base.ts:306. Without it, `marketingOptIn: false`
    // would either: (a) NOT stage (if the code used truthiness), or
    // (b) be re-applied identically to `marketingOptIn: undefined`.
    // Both are wrong — opting OUT is a valid recordable choice, distinct
    // from "field never submitted". The downstream `apply-consent` step
    // calls `applyConsentMarketing(username, false)` on a false stage; an
    // off-by-one would silently swallow opt-outs.
    const base = new ExposedBase();
    const ctx: InlineConsentCtx = {
      acceptance: { consentMarketing: true },
    };
    const wf = makeWf();
    base.consent(ctx, { marketingOptIn: false }, wf);
    expect(wf.lastCall).toBeUndefined();
    expect(ctx.pendingMarketingOptIn).toBe(false);
    // Distinct: field absent → no stage.
    const ctx2: InlineConsentCtx = { acceptance: { consentMarketing: true } };
    base.consent(ctx2, {}, wf);
    expect(ctx2.pendingMarketingOptIn).toBeUndefined();
  });
});
