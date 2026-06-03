export interface TArbacEvalResult<TScope> {
  allowed: boolean;
  scopes?: TScope[];
  /**
   * Present ONLY on an attenuated evaluation (`user.attenuate` was supplied).
   * The scopes from the credential's narrowed pass, to be CONJOINED with
   * `scopes` (the full-authority pass) by the scope layer — a row/field is
   * effective only if BOTH passes admit it. The conjunction is the scope
   * shape's responsibility (the engine is scope-agnostic), so the two unions
   * are surfaced separately here rather than pre-combined. Absent on a normal
   * (non-attenuated) evaluation.
   */
  credScopes?: TScope[];
}

export interface TArbacRole<TUserAttrs, TScope> {
  id: string;
  name?: string;
  description?: string;
  rules: Array<TArbacRule<TUserAttrs, TScope>>;
}

export type TArbacCompiledRule<TUserAttrs, TScope> = Omit<
  TArbacRule<TUserAttrs, TScope>,
  "resource" | "effect" | "_resourceRegex"
> & {
  _actionRegex: RegExp;
};

export interface TArbacRoleForResource<TUserAttrs, TScope> {
  id: string;
  allow: Array<TArbacCompiledRule<TUserAttrs, TScope>>;
  deny: Array<TArbacCompiledRule<TUserAttrs, TScope>>;
}

export type TArbacRule<TUserAttrs, TScope> =
  | {
      resource: string;
      action: string;
      scope?: (userAttrs: TUserAttrs, userId: string) => TScope;
      effect?: never;
    }
  | {
      resource: string;
      action: string;
      effect: "deny";
      scope?: never;
    };
