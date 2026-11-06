import { ARBAC_MESSAGES } from "@aooth/arbac-moost";
import { RATE_LIMIT_MESSAGES } from "@aooth/auth";
import { PASSWORD_POLICY_MESSAGES, USER_AUTH_ERROR_MESSAGES } from "@aooth/user";
import { DB_VALIDATOR_MESSAGES } from "@atscript/db";
import { VALIDATOR_MESSAGES } from "@atscript/typescript/utils";
import { AS_UI_MESSAGES } from "@atscript/ui/messages";
import { useTranslate } from "moost";
import { describe, expect, it } from "vite-plus/test";

// Importing the package registers every aooth catalogue (side effect of its modules).
import { AOOTH_HTTP_MESSAGES, AOOTH_MESSAGES } from "../index";
import { inLocale } from "./flow-utils";

// WHY: message codes live in ONE process-wide registry (moost's
// `registerMessages`) shared with every library: the last catalogue to
// register a code wins its English template (and bumps the translation
// generation). A generic aooth id would silently override — or be overridden
// by — another library's text, and an app's translation of the id would
// apply to both. These tests pin that aooth's ids cannot collide.

const AOOTH_CATALOGUES: Record<string, Readonly<Record<string, string>>> = {
  AOOTH_MESSAGES,
  AOOTH_HTTP_MESSAGES,
  ARBAC_MESSAGES,
  RATE_LIMIT_MESSAGES,
  PASSWORD_POLICY_MESSAGES,
  USER_AUTH_ERROR_MESSAGES,
};

/** The other catalogues an aooth server registers next to aooth's. */
const ECOSYSTEM_CATALOGUES: Record<string, Readonly<Record<string, string>>> = {
  VALIDATOR_MESSAGES, // @atscript/typescript — registered by moost-db and moost-wf
  DB_VALIDATOR_MESSAGES, // @atscript/db — registered by moost-db
  AS_UI_MESSAGES, // @atscript/ui — registered by moost-wf
};

/**
 * Ids aooth registers WITHOUT an aooth prefix (`AOOTH_`, `ARBAC_`, `PP_`).
 * Each names an aooth concept (MFA, OTP, passwords, invites, sign-in,
 * sessions, refresh tokens, SSO, the authorization server) — or is shared on
 * purpose (SHARED below). A new generic id must get a prefix instead.
 */
const SHARED: Record<string, string> = {
  // A UserAuthError type AND the sign-in workflow's error — one meaning, one text.
  INVALID_CREDENTIALS: "Invalid credentials",
  // A missing record, from any library (atscript-db's errors use it too).
  NOT_FOUND: "Not found",
  // The HTTP 429 of any rate limiter.
  RATE_LIMITED: "Too many requests. Retry after {retryAfter} s.",
};

const allCodes = (catalogues: Record<string, Readonly<Record<string, string>>>) =>
  Object.entries(catalogues).flatMap(([name, catalogue]) =>
    Object.entries(catalogue).map(([code, template]) => ({ name, code, template })),
  );

describe("aooth message codes in the shared registry", () => {
  it("no code is registered with two different templates (aooth + atscript-db + atscript-ui)", () => {
    const byCode = new Map<string, Array<{ name: string; template: string }>>();
    for (const { name, code, template } of allCodes({
      ...AOOTH_CATALOGUES,
      ...ECOSYSTEM_CATALOGUES,
    })) {
      byCode.set(code, [...(byCode.get(code) ?? []), { name, template }]);
    }
    const conflicts = [...byCode.entries()].filter(
      ([, entries]) => new Set(entries.map((e) => e.template)).size > 1,
    );
    expect(conflicts).toEqual([]);
  });

  it("every unprefixed aooth code names an aooth concept or is shared on purpose", () => {
    const aoothConcept =
      /(^|_)(MFA|TOTP|OTP|PASSWORD|PASSWORDS|INVITE|SIGN_IN|SIGNUP|SESSION|REFRESH_TOKEN|LOGOUT|LINKED_IDENTITY|RECOVERY|SSO|AUTHZ|USERNAME)(_|$)/;
    const generic = allCodes(AOOTH_CATALOGUES)
      .map(({ code }) => code)
      .filter((code) => !/^(AOOTH|ARBAC|PP)_/.test(code))
      .filter((code) => !aoothConcept.test(code) && !(code in SHARED));
    expect(generic).toEqual([]);
  });

  it("the shared codes keep their neutral English templates", () => {
    const registered = Object.fromEntries(
      allCodes(AOOTH_CATALOGUES)
        .filter(({ code }) => code in SHARED)
        .map(({ code, template }) => [code, template]),
    );
    expect(registered).toEqual(SHARED);
  });

  it("registering atscript-db's and atscript-ui's server packages after aooth leaves every aooth template in place", async () => {
    // Their modules register their catalogues on import — including any not
    // exported, which the static check above cannot see. Last one wins, so a
    // collision would show here as an aooth code answering another text.
    await import("@atscript/moost-db");
    await import("@atscript/moost-wf");
    const changed = inLocale(undefined, () => {
      const t = useTranslate();
      return allCodes(AOOTH_CATALOGUES)
        .filter(({ code, template }) => t(code) !== template)
        .map(({ name, code }) => `${name}.${code}`);
    });
    expect(changed).toEqual([]);
  });
});
