import type { PasswordPolicyDef } from "../types";
import { definePasswordPolicy } from "./policy";

/**
 * English templates of the built-in password policies' texts, by code: the
 * failure (`PP_*`, a policy's `errorMessage`) and the rule
 * (`PP_*_DESCRIPTION`, its `description`). Placeholders: `{min}`, `{max}`,
 * `{count}`. The templates are the plural forms; the policies' own English
 * texts are singular / plural-correct and are the fallback a translator
 * replaces. On a moost server `@aooth/auth-moost` registers them with
 * `registerMessages` on import.
 */
export const PASSWORD_POLICY_MESSAGES = {
  PP_MIN_LENGTH: "Password must be at least {min} characters long",
  PP_MIN_LENGTH_DESCRIPTION: "Minimum length {min}",
  PP_UPPERCASE: "Password must include at least {count} uppercase characters",
  PP_UPPERCASE_DESCRIPTION: "At least {count} uppercase characters",
  PP_LOWERCASE: "Password must include at least {count} lowercase characters",
  PP_LOWERCASE_DESCRIPTION: "At least {count} lowercase characters",
  PP_NUMBER: "Password must include at least {count} numbers",
  PP_NUMBER_DESCRIPTION: "At least {count} numbers",
  PP_SPECIAL_CHAR: "Password must include at least {count} special characters",
  PP_SPECIAL_CHAR_DESCRIPTION: "At least {count} special characters",
  PP_MAX_REPEATED: "Password must not have more than {max} consecutive repeated characters",
  PP_MAX_REPEATED_DESCRIPTION: "No more than {max} consecutive repeated characters",
} as const;

/** A code of {@link PASSWORD_POLICY_MESSAGES}. */
export type PasswordPolicyMessageCode = keyof typeof PASSWORD_POLICY_MESSAGES;

const plural = (n: number) => (n === 1 ? "" : "s");

export const ppHasMinLength = (min = 8): PasswordPolicyDef =>
  definePasswordPolicy({
    rule: (v: string, min: number) => v.length >= min,
    args: [min] as const,
    description: `Minimum length ${min}`,
    errorMessage: `Password must be at least ${min} characters long`,
    code: "PP_MIN_LENGTH",
    params: { min },
  });

export const ppHasUpperCase = (n = 1): PasswordPolicyDef =>
  definePasswordPolicy({
    rule: (v: string, n: number) => (v.match(/[A-Z]/g) || []).length >= n,
    args: [n] as const,
    description: `At least ${n} uppercase character${plural(n)}`,
    errorMessage: `Password must include at least ${n} uppercase character${plural(n)}`,
    code: "PP_UPPERCASE",
    params: { count: n },
  });

export const ppHasLowerCase = (n = 1): PasswordPolicyDef =>
  definePasswordPolicy({
    rule: (v: string, n: number) => (v.match(/[a-z]/g) || []).length >= n,
    args: [n] as const,
    description: `At least ${n} lowercase character${plural(n)}`,
    errorMessage: `Password must include at least ${n} lowercase character${plural(n)}`,
    code: "PP_LOWERCASE",
    params: { count: n },
  });

export const ppHasNumber = (n = 1): PasswordPolicyDef =>
  definePasswordPolicy({
    rule: (v: string, n: number) => (v.match(/\d/g) || []).length >= n,
    args: [n] as const,
    description: `At least ${n} number${plural(n)}`,
    errorMessage: `Password must include at least ${n} number${plural(n)}`,
    code: "PP_NUMBER",
    params: { count: n },
  });

export const ppHasSpecialChar = (n = 1): PasswordPolicyDef =>
  definePasswordPolicy({
    rule: (v: string, n: number) => (v.match(/[^A-Za-z0-9]/g) || []).length >= n,
    args: [n] as const,
    description: `At least ${n} special character${plural(n)}`,
    errorMessage: `Password must include at least ${n} special character${plural(n)}`,
    code: "PP_SPECIAL_CHAR",
    params: { count: n },
  });

export const ppMaxRepeatedChars = (maxRepeated = 2): PasswordPolicyDef =>
  definePasswordPolicy({
    rule: (v: string, maxRepeated: number) => !new RegExp(`(.)\\1{${maxRepeated},}`).test(v),
    args: [maxRepeated] as const,
    description: `No more than ${maxRepeated} consecutive repeated characters`,
    errorMessage: `Password must not have more than ${maxRepeated} consecutive repeated characters`,
    code: "PP_MAX_REPEATED",
    params: { max: maxRepeated },
  });
