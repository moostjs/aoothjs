import { ArbacUserProvider } from "../user.provider";

/**
 * Test utility — concrete ArbacUserProvider with stored userId / roles / attrs.
 *
 * `roles` is `public` (not `readonly`) so tests pinning the live-read invariant
 * of `useArbac().evaluate()` can mutate it between requests without re-instantiating.
 * `attrs` is parameterized so tests with non-empty attribute shapes use a typed default.
 *
 * NOT exported from the package's public entry; consumers should not depend on this.
 * Path: `@aooth/arbac-moost/src/__testing__/user-provider` — internal use only.
 */
export class FakeUserProvider<
  TAttrs extends object = Record<string, never>,
> extends ArbacUserProvider<TAttrs> {
  constructor(
    private readonly userId: string,
    public roles: string[],
    private readonly attrs: TAttrs = {} as TAttrs,
  ) {
    super();
  }
  override getUserId(): string {
    return this.userId;
  }
  override getRoles(): string[] {
    return this.roles;
  }
  override getAttrs(): TAttrs {
    return this.attrs;
  }
}
