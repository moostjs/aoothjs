import { Controller, Inherit, Injectable } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { createShadowStore } from "../workflow/auth-workflow";
import type { AuthWfCtx, AuthWfRecoveryDeliveryMode } from "../workflow/auth-workflow.ctx";
import type { AuthWorkflowOpts } from "../workflow/auth-workflow.opts";
import {
  FlowWorkflow,
  prepareFlowApp,
  type PrepareFlowOpts,
  type PreparedFlowApp,
  setPasswordInput,
} from "./flow-utils";

// Magic links (recovery + sign-in) through the real trigger: the link is the
// token the email outlet receives; the requester never sees it. Opening it
// shows a "Continue as …" step; submitting that step uses the link up.

let recoveryMode: AuthWfRecoveryDeliveryMode = "magicLink";
/** Test seam: rewrite a link's purpose after it is minted (the purpose-binding check). */
let tamperPurpose: "recovery" | "login" | undefined;
/** Test seam: the MFA policy mode (`'disabled'` lets a sign-in finish without a factor). */
let mfaMode: "optional" | "disabled" = "disabled";
/** Test seam: bind sign-in links to the requesting browser. */
let sameBrowser = false;

@Inherit()
@Injectable()
@Controller()
class MagicWorkflow extends FlowWorkflow {
  protected override resolveRecoveryDeliveryMode(): AuthWfRecoveryDeliveryMode {
    return recoveryMode;
  }
  protected override resolveAlternateCredentials(ctx: AuthWfCtx) {
    return {
      ...(super.resolveAlternateCredentials(ctx) as object),
      magicLink: true,
      magicLinkSameBrowser: sameBrowser,
    } as never;
  }
  protected override resolveMfaPolicy(ctx: AuthWfCtx) {
    const base = super.resolveMfaPolicy(ctx) as NonNullable<AuthWfCtx["mfaPolicy"]>;
    return { ...base, mode: mfaMode };
  }
  override async magicLinkSend(ctx: AuthWfCtx): Promise<unknown> {
    const out = await super.magicLinkSend(ctx);
    if (tamperPurpose && ctx.magicLink) ctx.magicLink.purpose = tamperPurpose;
    return out;
  }
}

const EMAIL = "alice@example.test";
const PASSWORD = "Password123!";

async function boot(
  workflowOpts: Partial<AuthWorkflowOpts> = {},
  flowOpts: Partial<PrepareFlowOpts> = {},
): Promise<PreparedFlowApp> {
  recoveryMode = "magicLink";
  tamperPurpose = undefined;
  mfaMode = "disabled";
  sameBrowser = false;
  return prepareFlowApp({
    workflowClass: MagicWorkflow,
    workflowOpts,
    ...flowOpts,
  });
}

/** Seed `alice@example.test` with a proven inbox; returns the user id. */
async function seedAlice(app: PreparedFlowApp, extras?: Record<string, unknown>): Promise<string> {
  const id = await app.seedUser(EMAIL, PASSWORD, extras);
  await app.users.setVerifiedEmail(id, EMAIL);
  return id;
}

async function requestRecovery(app: PreparedFlowApp, email: string) {
  const started = await app.start("auth/recovery/flow");
  return app.submit(started.body.wfs, { formData: { email } });
}

async function requestSignInLink(
  app: PreparedFlowApp,
  identifier: string,
  headers?: Record<string, string>,
) {
  const started = await app.start("auth/login/flow", headers);
  const atForm = await app.submit(started.body.wfs, { action: "magicLink" }, headers);
  expect(atForm.body.inputRequired).toBeDefined();
  return app.submit(atForm.body.wfs, { formData: { identifier } }, headers);
}

/** Open the emailed link: the "Continue as …" step (nothing used up yet). */
const open = (app: PreparedFlowApp, token: string, headers?: Record<string, string>) =>
  app.submit(token, {}, headers);

/** Open the link and continue: the link is used up. */
async function use(app: PreparedFlowApp, token: string, headers?: Record<string, string>) {
  const landing = await open(app, token, headers);
  expect(landing.body.inputRequired, JSON.stringify(landing.body)).toBeDefined();
  return app.submit(landing.body.wfs, { formData: {} }, headers);
}

const keysOf = (store: unknown) => [...(store as { store: Map<string, unknown> }).store.keys()];

describe("recovery magic link", () => {
  it("sends a single-use link; using it leads to the password step like a verified code", async () => {
    const app = await boot();
    const userId = await seedAlice(app);

    const sent = await requestRecovery(app, EMAIL);
    expect(sent.status).toBe(201);
    expect(sent.body).toEqual({ sent: true, outlet: "email" }); // no token for the requester
    expect(app.emails).toHaveLength(1);
    const [mail] = app.emails;
    expect(mail).toMatchObject({ target: EMAIL, template: "recovery.magicLink" });
    expect(mail.token).toMatch(/^magic-link\./);

    const atPassword = await use(app, mail.token);
    expect(JSON.stringify(atPassword.body.inputRequired)).toContain("newPassword");
    // The continuation is a fresh handle, never the link itself.
    expect(atPassword.body.wfs).toMatch(/^store\./);

    const done = await app.submit(atPassword.body.wfs, setPasswordInput);
    expect(done.body.finished).toBe(true);
    expect(await app.users.verifyPassword(userId, "NewPassword456!")).toBe(true);
    expect((await app.users.getUser(userId)).account.verifiedEmail).toBe(EMAIL);
  });

  it("opening the link does not use it up (mail scanners); continuing does — then it is gone (M1)", async () => {
    // WHY: a link consumed on first fetch is burned by a scanner that opens
    // it, and a sign-in link's session lands in the scanner's sandbox.
    const app = await boot();
    await seedAlice(app);
    await requestRecovery(app, EMAIL);
    const token = app.emails[0].token;
    const first = await open(app, token);
    const second = await open(app, token); // a scanner opened it first
    for (const landing of [first, second]) {
      expect(landing.body.inputRequired).toBeDefined();
      expect(landing.body.wfs).toBe(token); // still the link — not used up
      // The confirm step names the (masked) account the link is for.
      expect(JSON.stringify(landing.body)).toContain('"account":"a***e@example.test"');
    }
    const used = await app.submit(second.body.wfs, { formData: {} });
    expect(JSON.stringify(used.body.inputRequired)).toContain("newPassword");
    const replay = await open(app, token);
    expect(replay.status).toBe(410);
    expect(replay.body.inputRequired).toBeUndefined();
  });

  it("expires after magicLinkTtlMs", async () => {
    const app = await boot({ magicLinkTtlMs: 20 });
    await seedAlice(app);
    await requestRecovery(app, EMAIL);
    await new Promise((r) => setTimeout(r, 60));
    const late = await open(app, app.emails[0].token);
    expect(late.status).toBe(410);
    expect(late.body.inputRequired).toBeUndefined();
  });

  it("stores the link hashed: the store's key is not the token", async () => {
    const app = await boot();
    await seedAlice(app);
    await requestRecovery(app, EMAIL);
    const handle = app.emails[0].token.slice("magic-link.".length);
    const keys = keysOf(app.magicLinkStore);
    expect(keys).toHaveLength(1);
    expect(keys[0]).toMatch(/^wfh1_/);
    expect(keys.some((k) => k.includes(handle))).toBe(false);
  });

  it("answers an unknown identifier exactly like a known one, and sends nothing", async () => {
    const app = await boot();
    await seedAlice(app);
    const known = await requestRecovery(app, EMAIL);
    const unknown = await requestRecovery(app, "nobody@example.test");
    expect(unknown.status).toBe(known.status);
    expect(unknown.body).toEqual(known.body);
    expect(app.emails.map((e) => e.target)).toEqual([EMAIL]);
    // Each persisted one (hashed) link pause.
    expect(keysOf(app.magicLinkStore)).toHaveLength(2);
  });

  it("sends nothing to an inactive account: a pending invitee or a deactivated user (H2)", async () => {
    // WHY: with autoLoginOnRecover a recovery link to an inactive account
    // ended in a session for an account that must not sign in.
    const app = await boot({ autoLoginOnRecover: true });
    const pending = await app.users.createUser("pending@example.test", PASSWORD);
    await app.users.setVerifiedEmail(pending.id, "pending@example.test");
    const deactivated = await seedAlice(app);
    await app.users.deactivateAccount(deactivated);
    const a = await requestRecovery(app, "pending@example.test");
    const b = await requestRecovery(app, EMAIL);
    expect(a.body).toEqual({ sent: true, outlet: "email" });
    expect(b.body).toEqual({ sent: true, outlet: "email" });
    expect(app.emails).toHaveLength(0);
  });

  it("an account deactivated after the send gets no reset and no session (H2)", async () => {
    const app = await boot({ autoLoginOnRecover: true });
    const userId = await seedAlice(app);
    await requestRecovery(app, EMAIL);
    await app.users.deactivateAccount(userId);
    const used = await use(app, app.emails[0].token);
    expect(used.body.finished).toBe(true);
    expect(used.body.data).toBeUndefined();
    expect(JSON.stringify(used.body)).toContain("invalid or has expired");
    expect(await app.users.verifyPassword(userId, PASSWORD)).toBe(true);
  });

  it("sends at most one link per account within mfa.pincodeResendTimeoutMs, with the same answer", async () => {
    const app = await boot();
    await seedAlice(app);
    const first = await requestRecovery(app, EMAIL);
    const second = await requestRecovery(app, EMAIL);
    expect(second.body).toEqual(first.body);
    expect(app.emails).toHaveLength(1);
  });

  // WHY: the cooldown is a counter in `lockoutShadowStore`. The default memory
  // store is bounded; a flood of fresh counters (failed sign-ins for made-up
  // handles) must not evict it, or the next request would send another link.
  it("the resend wait survives a flood of other counters in a bounded store", async () => {
    const store = createShadowStore(4);
    const app = await boot({ lockoutShadowStore: store });
    await seedAlice(app);
    await requestRecovery(app, EMAIL);
    expect(app.emails).toHaveLength(1);
    for (let i = 0; i < 20; i++) await store.hit(`shadow-fail:flood-${i}`, 60_000);
    await requestRecovery(app, EMAIL);
    expect(app.emails).toHaveLength(1);
  });

  it("is bound to its purpose: a link whose purpose is not recovery cannot reset a password", async () => {
    const app = await boot();
    const userId = await seedAlice(app);
    tamperPurpose = "login";
    await requestRecovery(app, EMAIL);
    const used = await use(app, app.emails[0].token);
    expect(used.body.finished).toBe(true);
    expect(used.body.inputRequired).toBeUndefined();
    expect(JSON.stringify(used.body)).toContain("invalid or has expired");
    expect(await app.users.verifyPassword(userId, PASSWORD)).toBe(true);
  });

  it("'choice': the same picker for known and unknown identifiers; magicLink sends a link, otp a code", async () => {
    const app = await boot();
    recoveryMode = "choice";
    await seedAlice(app);
    const known = await requestRecovery(app, EMAIL);
    const unknown = await requestRecovery(app, "nobody@example.test");
    expect(known.body.wfs).toMatch(/^encapsulated\./);
    // The picker's client-held token carries nothing about the account (H3a).
    expect(String(unknown.body.wfs).length).toBe(String(known.body.wfs).length);
    expect(JSON.stringify(unknown.body).length).toBe(JSON.stringify(known.body).length);
    expect(unknown.body.inputRequired).toEqual(known.body.inputRequired);

    const linked = await app.submit(known.body.wfs, { formData: { mode: "magicLink" } });
    expect(linked.body).toEqual({ sent: true, outlet: "email" });
    expect(app.emails.at(-1)).toMatchObject({ template: "recovery.magicLink", target: EMAIL });

    const again = await requestRecovery(app, EMAIL);
    const coded = await app.submit(again.body.wfs, { formData: { mode: "otp" } });
    expect(JSON.stringify(coded.body.inputRequired)).toContain("code");
  });
});

describe("one store for the durable state and the links (H1)", () => {
  // WHY: the trigger picks the strategy from the token's prefix, and an
  // unhashed `store` strategy uses the token as the key — so a link's hashed
  // key, read from a shared table (backup, SQLi), opened as `store.<key>`.
  for (const purpose of ["recovery", "login"] as const) {
    it(`a ${purpose} link's stored key cannot be redeemed as a store token, and the link survives`, async () => {
      const app = await boot({}, { sharedStore: true });
      const userId = await seedAlice(app);
      if (purpose === "recovery") await requestRecovery(app, EMAIL);
      else await requestSignInLink(app, EMAIL);
      const key = keysOf(app.durableStore).find((k) => k.startsWith("wfh1_"));
      expect(key, "the link sits in the shared store").toBeTruthy();
      const attack = await app.submit(`store.${key}`, {});
      expect(attack.status).toBe(410);
      expect(attack.body.inputRequired).toBeUndefined();
      expect(attack.body.data).toBeUndefined();
      expect(await app.users.verifyPassword(userId, PASSWORD)).toBe(true);
      // The attempt did not destroy the link: its owner still gets in.
      const used = await use(app, app.emails[0].token);
      expect(used.status).toBe(201);
      expect(JSON.stringify(used.body)).not.toContain("invalid or has expired");
    });
  }
});

describe("magic-link sign-in", () => {
  it("signs a user without MFA in from the link; the requester gets no token", async () => {
    const app = await boot();
    const userId = await seedAlice(app);
    const sent = await requestSignInLink(app, EMAIL);
    expect(sent.body).toEqual({ sent: true, outlet: "email" });
    expect(app.emails).toHaveLength(1);
    expect(app.emails[0]).toMatchObject({ target: EMAIL, template: "login.magicLink" });

    const done = await use(app, app.emails[0].token);
    expect(done.body.finished).toBe(true);
    const data = done.body.data as { accessToken?: string };
    expect((await app.auth.validate(data.accessToken!))?.userId).toBe(userId);
  });

  it("satisfies only the first factor: a user with MFA is challenged after the click", async () => {
    const app = await boot();
    mfaMode = "optional";
    await seedAlice(app, {
      mfa: {
        methods: [{ name: "totp", value: "JBSWY3DPEHPK3PXP", confirmed: true }],
        defaultMethod: "totp",
      },
    });
    await requestSignInLink(app, EMAIL);
    const clicked = await use(app, app.emails[0].token);
    expect(clicked.body.finished).toBeUndefined();
    expect(clicked.body.inputRequired).toBeDefined();
    expect(JSON.stringify(clicked.body)).not.toContain("accessToken");
    expect(clicked.body.wfs).toMatch(/^store\./);
    // The same challenge a password sign-in gets.
    const byPassword = await app.login(EMAIL, PASSWORD);
    expect(clicked.body.inputRequired).toEqual(byPassword.body.inputRequired);
  });

  it("an initial (must-change) password is changed first, as after a password sign-in (L6)", async () => {
    // WHY: a link proves the inbox, not the password policy.
    const app = await boot();
    const userId = await seedAlice(app);
    await app.users.update(userId, { password: { isInitial: true } } as never);
    await requestSignInLink(app, EMAIL);
    const used = await use(app, app.emails[0].token);
    expect(used.body.finished).toBeUndefined();
    expect(JSON.stringify(used.body.inputRequired)).toContain("newPassword");
  });

  it("answers unknown, inactive and locked accounts like a known one, and sends nothing", async () => {
    const app = await boot();
    await seedAlice(app);
    const inactive = await app.users.createUser("bob@example.test", PASSWORD);
    await app.users.setVerifiedEmail(inactive.id, "bob@example.test");
    const lockedId = await app.seedUser("carol@example.test", PASSWORD);
    await app.users.setVerifiedEmail(lockedId, "carol@example.test");
    await app.users.lockAccount(lockedId, "admin", 60_000);

    const known = await requestSignInLink(app, EMAIL);
    for (const who of ["nobody@example.test", "bob@example.test", "carol@example.test"]) {
      const res = await requestSignInLink(app, who);
      expect(res.status).toBe(known.status);
      expect(res.body).toEqual(known.body);
    }
    expect(app.emails.map((e) => e.target)).toEqual([EMAIL]);
  });

  it("never sends to an unproven address", async () => {
    const app = await boot();
    await app.seedUser(EMAIL, PASSWORD); // no verified email, no email MFA
    await requestSignInLink(app, EMAIL);
    expect(app.emails).toHaveLength(0);
  });

  it("is single use, and a lock set after sending refuses the link", async () => {
    const app = await boot();
    const userId = await seedAlice(app);
    await requestSignInLink(app, EMAIL);
    const token = app.emails[0].token;
    await app.users.lockAccount(userId, "admin", 60_000);
    const refused = await use(app, token);
    expect(refused.body.finished).toBe(true);
    expect(refused.body.data).toBeUndefined();
    expect(JSON.stringify(refused.body)).toContain("invalid or has expired");
    expect((await open(app, token)).status).toBe(410);
  });

  it("is bound to its purpose: a link whose purpose is not login cannot sign in", async () => {
    const app = await boot();
    await seedAlice(app);
    tamperPurpose = "recovery";
    await requestSignInLink(app, EMAIL);
    const used = await use(app, app.emails[0].token);
    expect(used.body.finished).toBe(true);
    expect(used.body.data).toBeUndefined();
  });

  it("magicLinkSameBrowser: the link works only in the browser that asked for it (M1)", async () => {
    // WHY: a forwarded sign-in link would otherwise log the victim into the
    // sender's account (login CSRF). Opt-in: other devices are legitimate.
    const app = await boot({ mfa: { pincodeResendTimeoutMs: 1 } });
    sameBrowser = true;
    await seedAlice(app);
    const sentHere = async () => {
      const res = await requestSignInLink(app, EMAIL);
      const cookie = res.setCookies.find((c) => c.startsWith("aooth_magic_link="));
      expect(cookie, "the binding cookie is set").toBeDefined();
      await new Promise((r) => setTimeout(r, 5)); // past the 1 ms cooldown
      return { cookie: cookie!.split(";")[0] };
    };

    // Opened elsewhere (no cookie): refused, nothing issued.
    await sentHere();
    const elsewhere = await use(app, app.emails.at(-1)!.token);
    expect(elsewhere.body.data).toBeUndefined();
    expect(JSON.stringify(elsewhere.body)).toContain("invalid or has expired");

    // Opened in the browser that asked for it: signed in.
    const jar = await sentHere();
    const here = await use(app, app.emails.at(-1)!.token, jar);
    expect(here.body.finished).toBe(true);
    expect((here.body.data as { accessToken?: string }).accessToken).toBeTruthy();
  });
});

describe("the Quick Start walkthroughs (docs/guide/quick-start.md)", () => {
  // WHY: the guide's curl sequences must work exactly as written.
  it("password reset: start → email → open link → continue → new password", async () => {
    const app = await boot();
    const userId = await seedAlice(app);
    const s1 = await app.post("/auth/trigger", { wfid: "auth/recovery/flow" });
    expect(s1.body.inputRequired).toBeDefined();
    const s2 = await app.post("/auth/trigger", {
      wfs: s1.body.wfs,
      input: { formData: { email: EMAIL } },
    });
    expect(s2.body).toEqual({ sent: true, outlet: "email" });
    const s3 = await app.post("/auth/trigger", { wfs: app.emails[0].token });
    expect(s3.body.inputRequired).toBeDefined();
    const s4 = await app.post("/auth/trigger", { wfs: s3.body.wfs, input: { formData: {} } });
    expect(s4.body.inputRequired).toBeDefined();
    const s5 = await app.post("/auth/trigger", {
      wfs: s4.body.wfs,
      input: {
        formData: {
          newPassword: "NewCorrectHorse42!",
          confirmPassword: "NewCorrectHorse42!",
          consents: [],
        },
      },
    });
    expect(s5.body.finished).toBe(true);
    expect(await app.users.verifyPassword(userId, "NewCorrectHorse42!")).toBe(true);
  });

  it("magic-link login: start → magicLink action → identifier → open link → continue", async () => {
    const app = await boot();
    await seedAlice(app);
    const s1 = await app.post("/auth/trigger", { wfid: "auth/login/flow" });
    const s2 = await app.post("/auth/trigger", {
      wfs: s1.body.wfs,
      input: { action: "magicLink" },
    });
    expect(s2.body.inputRequired).toBeDefined();
    const s3 = await app.post("/auth/trigger", {
      wfs: s2.body.wfs,
      input: { formData: { identifier: EMAIL } },
    });
    expect(s3.body).toEqual({ sent: true, outlet: "email" });
    const s4 = await app.post("/auth/trigger", { wfs: app.emails[0].token });
    expect(s4.body.inputRequired).toBeDefined();
    const s5 = await app.post("/auth/trigger", { wfs: s4.body.wfs, input: { formData: {} } });
    expect(s5.body.finished).toBe(true);
  });
});
