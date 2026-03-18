import type { PasswordPolicyDef } from "../types";

export const ppHasMinLength = (min = 8): PasswordPolicyDef => ({
  rule: `v.length >= ${min}`,
  description: `Minimum length ${min}`,
  errorMessage: `Password must be at least ${min} characters long`,
});

export const ppHasUpperCase = (n = 1): PasswordPolicyDef => ({
  rule: `(v.match(/[A-Z]/g) || []).length >= ${n}`,
  description: `At least ${n} uppercase character${n === 1 ? "" : "s"}`,
  errorMessage: `Password must include at least ${n} uppercase character${n === 1 ? "" : "s"}`,
});

export const ppHasLowerCase = (n = 1): PasswordPolicyDef => ({
  rule: `(v.match(/[a-z]/g) || []).length >= ${n}`,
  description: `At least ${n} lowercase character${n === 1 ? "" : "s"}`,
  errorMessage: `Password must include at least ${n} lowercase character${n === 1 ? "" : "s"}`,
});

export const ppHasNumber = (n = 1): PasswordPolicyDef => ({
  rule: `(v.match(/\\d/g) || []).length >= ${n}`,
  description: `At least ${n} number${n === 1 ? "" : "s"}`,
  errorMessage: `Password must include at least ${n} number${n === 1 ? "" : "s"}`,
});

export const ppHasSpecialChar = (n = 1): PasswordPolicyDef => ({
  rule: `(v.match(/[^A-Za-z0-9]/g) || []).length >= ${n}`,
  description: `At least ${n} special character${n === 1 ? "" : "s"}`,
  errorMessage: `Password must include at least ${n} special character${n === 1 ? "" : "s"}`,
});

export const ppMaxRepeatedChars = (maxRepeated = 2): PasswordPolicyDef => ({
  rule: `/(.)\\1{${maxRepeated},}/.test(v) === false`,
  description: `No more than ${maxRepeated} consecutive repeated characters`,
  errorMessage: `Password must not have more than ${maxRepeated} consecutive repeated characters`,
});
