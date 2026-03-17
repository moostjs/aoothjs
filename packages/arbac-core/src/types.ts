export interface TArbacEvalResult<TScope> {
  allowed: boolean;
  scopes?: TScope[];
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
      scope?: (userAttrs: TUserAttrs) => TScope;
      effect?: never;
    }
  | {
      resource: string;
      action: string;
      effect: "deny";
      scope?: never;
    };
