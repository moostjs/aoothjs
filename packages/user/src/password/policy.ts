import type {
  PasswordPolicyContext,
  PasswordPolicyDef,
  PasswordPolicyEvalFn,
  PasswordPolicyInstance,
} from "../types";
import { FtringsPool } from "@prostojs/ftring";

const fnPool = new FtringsPool<boolean, { v: string; context?: PasswordPolicyContext }>();

export function normalizePolicies(
  policies?: (PasswordPolicyDef | PasswordPolicyInstance)[],
): PasswordPolicy[] {
  return (policies || []).map((p) => (p instanceof PasswordPolicy ? p : new PasswordPolicy(p)));
}

export class PasswordPolicy implements PasswordPolicyInstance {
  readonly rule: string | PasswordPolicyEvalFn;
  readonly description: string;
  readonly errorMessage: string;

  constructor(config: PasswordPolicyDef) {
    this.rule = config.rule;
    this.description = config.description || "";
    this.errorMessage = config.errorMessage || "";
  }

  protected _evalFn!: PasswordPolicyEvalFn;

  evaluate(password: string, context?: PasswordPolicyContext): boolean | Promise<boolean> {
    if (!this._evalFn) {
      if (typeof this.rule === "function") {
        this._evalFn = this.rule;
      } else if (typeof this.rule === "string" && this.rule) {
        const fn = fnPool.getFn(this.rule);
        this._evalFn = (v, ctx) => fn({ v, context: ctx });
      } else {
        this._evalFn = () => true;
      }
    }
    return this._evalFn(password, context);
  }

  get transferable(): boolean {
    return typeof this.rule === "string";
  }
}
