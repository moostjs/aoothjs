import type {
  PasswordPolicyContext,
  PasswordPolicyDef,
  PasswordPolicyEvalFn,
  PasswordPolicyInstance,
} from "../types";

export function normalizePolicies(
  policies?: (PasswordPolicyDef | PasswordPolicyInstance)[],
): PasswordPolicy[] {
  return (policies || []).map((p) => (p instanceof PasswordPolicy ? p : new PasswordPolicy(p)));
}

/**
 * Helper that builds a `PasswordPolicyDef` from a real backend function plus
 * its bound positional arguments. The function runs directly on the server
 * (no sandbox, no eval); `serialized` is auto-derived as
 * `(v) => (${rule.toString()})(v, ${args.map(JSON.stringify).join(', ')})`
 * so the same constraint can ship to the frontend without re-implementing it.
 *
 * Bundler-safe: positional invocation means renamed parameters inside the
 * function body stay consistent — the call site only relies on argument
 * ORDER, not identifier preservation.
 *
 * Constraint on the rule body: it MUST reference only its own parameters.
 * No closures over module imports, no `this`, no helpers from outer scope —
 * `rule.toString()` ships the literal source; any free identifier the
 * frontend cannot resolve breaks transferability. (`String.prototype.match`,
 * regex literals, plain JS globals are fine.)
 *
 * Omit `args` to mark the policy backend-only — `serialized` stays
 * `undefined` and `transferable` is false; frontend pre-validation skips it
 * and only the server check enforces the rule.
 */
export function definePasswordPolicy<A extends readonly unknown[]>(opts: {
  rule: (v: string, ...args: A) => boolean | Promise<boolean>;
  args?: A;
  description?: string;
  errorMessage?: string;
}): PasswordPolicyDef {
  const { rule, args, description, errorMessage } = opts;
  const bound: PasswordPolicyEvalFn = args
    ? (v) => rule(v, ...args)
    : (v) => rule(v, ...([] as unknown as A));
  const def: PasswordPolicyDef = { rule: bound };
  if (args) {
    const argList = args.map((a) => JSON.stringify(a)).join(", ");
    def.serialized =
      argList.length > 0
        ? `(v) => (${rule.toString()})(v, ${argList})`
        : `(v) => (${rule.toString()})(v)`;
  }
  if (description !== undefined) def.description = description;
  if (errorMessage !== undefined) def.errorMessage = errorMessage;
  return def;
}

export class PasswordPolicy implements PasswordPolicyInstance {
  readonly rule: PasswordPolicyEvalFn;
  readonly serialized?: string;
  readonly description: string;
  readonly errorMessage: string;

  constructor(config: PasswordPolicyDef) {
    this.rule = config.rule;
    if (config.serialized !== undefined) this.serialized = config.serialized;
    this.description = config.description || "";
    this.errorMessage = config.errorMessage || "";
  }

  evaluate(password: string, context?: PasswordPolicyContext): boolean | Promise<boolean> {
    return this.rule(password, context);
  }

  get transferable(): boolean {
    return this.serialized !== undefined;
  }
}
