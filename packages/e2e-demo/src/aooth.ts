import {
  getAoothCredentialMetadataSpec,
  getAoothUserHandleSpec,
} from "@aooth/arbac-moost/atscript";
import { AuthCredential } from "@aooth/auth";
import { type AuthCredentialTable, CredentialStoreAtscriptDb } from "@aooth/auth/atscript-db";
import type { BuildMagicLinkUrl } from "@aooth/auth-moost";
import { definePasswordPolicy, type UserCredentials, UserService } from "@aooth/user";
import { type AuthUserTable, UsersStoreAtscriptDb } from "@aooth/user/atscript-db";

import type { AppDb } from "./db";
import type { AppEnv } from "./env";
import { DemoAuthCredential } from "./models/auth-credential.as";
import { DemoUser } from "./models/user.as";
import { readVariantHeader } from "./variants-server";

/**
 * Default `roles` (inherited array) and mirror `username` → `email` so the
 * bundled invite flow gets a usable contact field.
 *
 * `tenantId` defaults are wired via `InviteWorkflowOptions.prepareUser` for
 * the bundled invite flow; this store-level fallback covers programmatic
 * `createUser` calls (seeders, admin scripts) that bypass the workflow hook.
 */
class DemoUserStore extends UsersStoreAtscriptDb<DemoUser> {
  async create(data: UserCredentials & DemoUser): Promise<void> {
    const rec = data as unknown as Record<string, unknown>;
    const patched = {
      ...rec,
      roles: Array.isArray(rec.roles) ? rec.roles : [],
      email: typeof rec.email === "string" ? rec.email : data.username,
      tenantId:
        typeof rec.tenantId === "string" && rec.tenantId.length > 0 ? rec.tenantId : "_global",
    } as unknown as UserCredentials & DemoUser;
    return super.create(patched);
  }
}

export interface AppAuthOptions {
  tables: AppDb["tables"];
  env: AppEnv;
}

export interface AppAuth {
  authCredential: AuthCredential<Record<string, unknown>>;
  credentialStore: CredentialStoreAtscriptDb<Record<string, unknown>>;
  userStore: DemoUserStore;
  userService: UserService<DemoUser>;
  buildMagicLinkUrl: BuildMagicLinkUrl;
  /**
   * Resolved `@aooth.user.email` / `@aooth.user.phone` handle-column names
   * (or `undefined` when the model doesn't annotate one / it lacks a unique
   * index). `DemoAuthWorkflow.resolvePromoteHandleField` returns these to turn
   * channel→handle promotion ON for the demo.
   */
  emailField: string | undefined;
  phoneField: string | undefined;
}

export function createAooth({ tables, env }: AppAuthOptions): AppAuth {
  // Resolve the login-handle field names ONCE from the model's `@aooth.user.*`
  // annotations (the spec is WeakMap-cached per type). The store then iterates a
  // precomputed field list per `findByHandle` — zero annotation reflection on
  // the hot path. Warn-and-disable: a handle field missing `@db.index.unique` is
  // dropped here (login by it becomes unavailable). DemoUser annotates both
  // `email` and `phone` with a unique index, so `warnings` is empty in practice.
  const handles = getAoothUserHandleSpec(DemoUser);
  for (const warning of handles.warnings) {
    console.warn(`[aooth] ${warning}`);
  }
  // `AtscriptDbTable` returns `Record<string, unknown>` from its structural
  // reads, so the typed `AuthUserTable` surface needs a cast at the wiring
  // seam — same pattern `wf-store.ts` uses.
  const userStore = new DemoUserStore({
    table: tables.users as unknown as AuthUserTable<DemoUser>,
    handleFields: handles.handleFields,
  });

  const userService = new UserService<DemoUser>(userStore, {
    // Canonical correspondence column for `getCorrespondenceEmail` — the same
    // `@aooth.user.email`-annotated field the store uses for handle lookups.
    // Resolution order: this column → `account.verifiedEmail` (written by the
    // invite accept tail) → confirmed email-MFA method.
    emailField: handles.emailField,
    password: {
      historyLength: 5,
      // 1-year rotation policy (a typical B2B compliance requirement that
      // motivated the upstream feature in PW_EXP.md). The
      // demo seeds one user (t1_stale) with `password.lastChanged` deep in
      // the past so the `password-expired` login variant lands deterministically
      // on `SetPasswordForm` regardless of when the demo is booted. All other
      // seeded users get `lastChanged = Date.now()` and stay well inside the
      // window.
      maxAgeMs: 365 * 24 * 60 * 60 * 1000,
      // Transferable function rules: `definePasswordPolicy` runs the fn on
      // the backend directly (no sandbox) AND ships a `(v) => (fn)(v, ...args)`
      // text form via `getTransferablePolicies()` for cross-tier pre-validation.
      policies: [
        definePasswordPolicy({
          rule: (v: string, min: number) => v.length >= min,
          args: [8] as const,
          description: "At least 8 characters",
          errorMessage: "Password must be at least 8 characters long",
        }),
        definePasswordPolicy({
          rule: (v: string) => /[A-Za-z]/.test(v),
          args: [] as const,
          description: "Contains a letter",
          errorMessage: "Password must contain at least one letter",
        }),
        definePasswordPolicy({
          rule: (v: string) => /[0-9]/.test(v),
          args: [] as const,
          description: "Contains a digit",
          errorMessage: "Password must contain at least one digit",
        }),
      ],
    },
    lockout: {
      threshold: env.LOCKOUT_THRESHOLD,
      duration: env.LOCKOUT_DURATION_MS,
    },
    // Required to use trusted-device APIs (issue/verify HMAC-signed tokens).
    // The `device-trust` login variant relies on this; without a secret the
    // workflow throws on `issueTrustedDevice` and the MFA step never finishes.
    deviceTrust: { secret: env.JWT_SECRET },
  });

  // Resolve the credential-METADATA column name from the model's
  // `@aooth.auth.metadata` annotation (WeakMap-cached, same contract as the
  // handle spec above). Warn-and-disable: an annotated field without
  // `@db.json` is dropped here (metadata is then not persisted).
  // `DemoAuthCredential` annotates its typed `metadata` column, so
  // `metadataField` is `"metadata"` and `warnings` is empty in practice.
  const credSpec = getAoothCredentialMetadataSpec(DemoAuthCredential);
  for (const warning of credSpec.warnings) {
    console.warn(`[aooth] ${warning}`);
  }
  // Stateful, enumerable credential store backed by the app's SQLite DB. A
  // stateful store is what makes the "active sessions" panel possible —
  // `listSessions` / `revokeSession` / `revokeOtherSessions` need to enumerate
  // a user's token families, which a stateless JWT store can't do.
  const credentialStore = new CredentialStoreAtscriptDb<Record<string, unknown>>({
    table: tables.credentials as unknown as AuthCredentialTable<Record<string, unknown>>,
    metadataField: credSpec.metadataField,
  });

  const authCredential = new AuthCredential<Record<string, unknown>>({
    store: credentialStore,
    method: "token",
    accessTtl: env.ACCESS_TTL_MS,
    refresh: {
      ttl: env.REFRESH_TTL_MS,
      rotation: "always",
    },
    // Real activity time for the sessions panel — cheap (piggybacks the
    // rotation write on each refresh).
    trackLastSeen: "refresh",
  });

  const buildMagicLinkUrl: BuildMagicLinkUrl = (kind, token, ctx) => {
    const segment = kind === "recovery.magicLink" ? "recover" : "accept-invite";
    // `uid` rides on the URL so the SPA can call `/auth/invite/post-redemption`
    // when a re-click on an already-redeemed invite link hits a 410 from the
    // wf state store. Recovery links don't need it (auth-moost's outlet
    // doesn't surface userId for `recovery.magicLink` either). See
    // WF-INVITE-010 in `test-e2e/invite.spec.ts`.
    const uidParam = ctx?.userId ? `&uid=${encodeURIComponent(ctx.userId)}` : "";
    // Propagate the `x-wf-variant` request header (admin leg of an invite,
    // or the user's recovery trigger) onto the magic-link URL so the
    // invitee / recoverer's resume request lands on the SAME variant the
    // originator selected. The SPA's WfPage reads `?variant=…` and forwards
    // it as the `x-wf-variant` header on every resume request, which is
    // what DemoConsentStore.getPendingConsents keys off. Without this,
    // `prepare-consents` on the resume leg sees no variant header and
    // returns an empty pending-consents list — even when the originator's
    // variant declared a non-empty consent universe.
    const variant = readVariantHeader();
    const variantParam = variant ? `&variant=${encodeURIComponent(variant)}` : "";
    return `${env.FRONTEND_URL}/${segment}?wfs=${token}${uidParam}${variantParam}`;
  };

  return {
    authCredential,
    credentialStore,
    userStore,
    userService,
    buildMagicLinkUrl,
    emailField: handles.emailField,
    phoneField: handles.phoneField,
  };
}
