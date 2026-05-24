/**
 * `AuthOpts` — centralized cross-workflow infrastructure defaults. Singleton DI
 * instance shared by `LoginWorkflow`, `InviteWorkflow`, and `RecoveryWorkflow`.
 *
 * Customers override by extending this class and registering the replacement
 * via moost's `createReplaceRegistry()` / `app.setReplaceRegistry(...)`. The
 * three auth workflows resolve `AuthOpts` from DI in their constructors and
 * read fields directly — `this.authOpts.mfa.pincodeLength`, etc.
 *
 * Out of scope for this provider:
 *   - Per-workflow infrastructure (e.g. login's `deviceTrust` cookie binding,
 *     login's form-schema map) stays on each workflow's per-instance opts pojo.
 *   - Policy (per-tenant / per-user / per-request flags) lives on the
 *     `resolveXxx(ctx)` resolver surface on each workflow class.
 */
import { Injectable } from "moost";

@Injectable()
export class AuthOpts {
  /** Pincode infrastructure shared by login MFA, invite MFA, and recovery OTP. */
  mfa = {
    pincodeLength: 6,
    pincodeTtlMs: 5 * 60 * 1000,
    pincodeResendTimeoutMs: 60_000,
  };
  /** Magic-link TTL shared by login (alt-credentials), invite, recovery. */
  magicLinkTtlMs = 60 * 60 * 1000;
  /** Canonical login URL — used by invite (post-accept redirect) and recovery (abort-to-login + post-reset redirect) as the resolver-default loginUrl. */
  loginUrl = "/login";
  /** TOTP provisioning issuer — used by login MFA and invite MFA enrollment. */
  totpIssuer = "aooth";
}
