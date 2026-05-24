/**
 * `AuthOpts` default values pin — these are the cross-workflow infrastructure
 * defaults read by the three bundled auth workflows. A drift in any one of
 * these silently changes runtime behaviour for every consumer that doesn't
 * register a replacement, so the test fails loud if a default moves.
 */
import { describe, expect, it } from "vite-plus/test";

import { AuthOpts } from "../auth.opts";

describe("AuthOpts — default values", () => {
  it("ships sensible cross-workflow defaults (pincode timers, magic-link TTL, loginUrl, totpIssuer)", () => {
    const opts = new AuthOpts();
    expect(opts.mfa.pincodeLength).toBe(6);
    expect(opts.mfa.pincodeTtlMs).toBe(5 * 60 * 1000);
    expect(opts.mfa.pincodeResendTimeoutMs).toBe(60_000);
    expect(opts.magicLinkTtlMs).toBe(60 * 60 * 1000);
    expect(opts.loginUrl).toBe("/login");
    expect(opts.totpIssuer).toBe("aooth");
  });
});
