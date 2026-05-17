import { AuthCredential, CredentialStoreJwt, DenylistStoreMemory } from "@aooth/auth";
import type { BuildMagicLinkUrl } from "@aooth/auth-moost";
import { type UserCredentials, UserService } from "@aooth/user";
import { type AuthUserTable, UsersStoreAtscriptDb } from "@aooth/user/atscript-db";

import type { AppDb } from "./db";
import type { AppEnv } from "./env";
import type { DemoUser } from "./models/user.as";

/**
 * Default `roles` (inherited array) and mirror `username` → `email` so the
 * bundled invite flow gets a usable contact field.
 *
 * `tenantId` defaults are wired via `InviteWorkflowOptions.prepareUser` for
 * the bundled invite flow; this store-level fallback covers programmatic
 * `createUser` calls (seeders, admin scripts) that bypass the workflow hook.
 *
 * `findByUsername` falls back to email lookup so the bundled recovery flow
 * (which calls `userService.getUser(input.email)`) can resolve users in this
 * app where username is a short handle and email is the canonical contact.
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

  async findByUsername(handle: string): Promise<(UserCredentials & DemoUser) | null> {
    const byUsername = await super.findByUsername(handle);
    if (byUsername) return byUsername;
    const byEmail = await this.table.findOne({ filter: { email: handle } });
    return (byEmail as (UserCredentials & DemoUser) | null) ?? null;
  }
}

export interface AppAuthOptions {
  tables: AppDb["tables"];
  env: AppEnv;
}

export interface AppAuth {
  authCredential: AuthCredential<Record<string, unknown>>;
  credentialStore: CredentialStoreJwt<Record<string, unknown>>;
  userStore: DemoUserStore;
  userService: UserService<DemoUser>;
  buildMagicLinkUrl: BuildMagicLinkUrl;
  denylist: DenylistStoreMemory;
}

export function createAooth({ tables, env }: AppAuthOptions): AppAuth {
  // Single shared denylist: `validate` consults it by raw token, the JWT store
  // consults it by jti — keyspaces are disjoint so reuse is safe.
  const denylist = new DenylistStoreMemory();

  // `AtscriptDbTable` returns `Record<string, unknown>` from its structural
  // reads, so the typed `AuthUserTable` surface needs a cast at the wiring
  // seam — same pattern `wf-store.ts` uses.
  const userStore = new DemoUserStore({
    table: tables.users as unknown as AuthUserTable<DemoUser>,
  });

  const userService = new UserService<DemoUser>(userStore, {
    password: {
      historyLength: 5,
      // Transferable string rules so the same policy can pre-validate on the
      // frontend. `v` is the candidate password.
      policies: [
        {
          rule: "v.length >= 8",
          description: "At least 8 characters",
          errorMessage: "Password must be at least 8 characters long",
        },
        {
          rule: "/[A-Za-z]/.test(v)",
          description: "Contains a letter",
          errorMessage: "Password must contain at least one letter",
        },
        {
          rule: "/[0-9]/.test(v)",
          description: "Contains a digit",
          errorMessage: "Password must contain at least one digit",
        },
      ],
    },
    lockout: {
      threshold: env.LOCKOUT_THRESHOLD,
      duration: env.LOCKOUT_DURATION_MS,
    },
  });

  const credentialStore = new CredentialStoreJwt<Record<string, unknown>>({
    algorithm: "HS256",
    secret: env.JWT_SECRET,
    denylist,
  });

  const authCredential = new AuthCredential<Record<string, unknown>>({
    store: credentialStore,
    method: "token",
    accessTtl: env.ACCESS_TTL_MS,
    refresh: {
      ttl: env.REFRESH_TTL_MS,
      // Stateless JWT: `sliding` degrades to `always` anyway. Be explicit.
      rotation: "always",
    },
    denylist,
  });

  const buildMagicLinkUrl: BuildMagicLinkUrl = (kind, token) => {
    const segment = kind === "recovery.magicLink" ? "recover" : "accept-invite";
    return `${env.FRONTEND_URL}/${segment}?wfs=${token}`;
  };

  return {
    authCredential,
    credentialStore,
    userStore,
    userService,
    buildMagicLinkUrl,
    denylist,
  };
}
