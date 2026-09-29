# Credential Attenuation

Credential attenuation lets one user mint a **scoped token** — a personal access token (PAT), a CI token, a share link — that carries _less_ authority than the user holds. A token can only **narrow**; it never grants anything the user lacks. Aoothjs implements this as a typed-field bridge between the auth credential and the ARBAC engine: the credential model declares which of its per-token payload fields are _attenuators_, and at request time those values intersect the user's full authority down to what the token is allowed to do. An ordinary token (no attenuator field set) is unaffected and evaluates exactly as before.

```ts
// Mint a PAT that can only act as `viewer`, only inside tenant t-1:
await auth.issue(userId, {
  kind: "pat",
  ttl: 90 * 24 * 3_600_000,
  assumedRoles: ["viewer"], // @arbac.attenuate.role column on the credential model
  scopedTenant: "t-1", // @arbac.attenuate.attr "tenantId" column
});
```

## Declaring attenuator fields

Two annotations in the `@arbac.attenuate.*` namespace mark attenuator fields on the credential `.as` model. They are registered by `@aooth/arbac-moost/plugin` alongside `@arbac.role` / `@arbac.attribute` / `@arbac.userId`:

| Annotation                        | Marks                                                                                                                                                               |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@arbac.attenuate.role`           | The ONE field holding the assumed-role subset (`string[]`). More than one such field throws at boot.                                                                |
| `@arbac.attenuate.attr "attrKey"` | A field whose value narrows the named USER attribute — the argument is a key in the same map `@arbac.attribute` feeds. Multiple fields, each a different attribute. |

Attenuator fields are ordinary typed per-token payload fields — set them via [`IssueOptions`](/api/auth#issueoptions-tpayload) at mint time, leave them unset for a full-authority token.

## Runtime wiring

The runtime half lives in `@aooth/arbac-moost/atscript`. The ARBAC user provider exposes an optional `getAttenuation()` seam — override it to bridge the validated credential into claims:

```ts
@Injectable()
class AppUserProvider extends AtscriptArbacUserProvider<AppUser> {
  // ...ctor + getUserId() as usual...
  override getAttenuation() {
    return extractAttenuation(AppCredential, useAuth().getAuthContext());
  }
}
```

`extractAttenuation` walks the model's `@arbac.attenuate.*` annotations against the flat auth context and returns [`AoothArbacClaims`](/api/arbac-moost#aootharbacclaims) (`{ roles?, attrs?, allowUnheldRoles? }`) — or `undefined` when no attenuator field is set, so a normal token costs nothing.

Call `validateAttenuationTargets(AppCredential, knownUserAttrKeys)` **once at boot**: it fails loud if any `@arbac.attenuate.attr` targets a key that is not a real user attribute, catching a typo'd target before it silently breaks authorization.

## Intersection, not union — the soundness boundary

Attenuation is the restrictive mirror of the additive [scope-merging helpers](./scopes), and confusing the two is the central footgun. The engine never _grants_ from a credential: with claims present, [`Arbac.evaluate`](/api/arbac-core) runs the policy **twice** — full roles, then attenuated roles — and intersects the OUTCOMES (`allowed` only if both passes allow; the attenuated scopes come back as `credScopes`). `useArbac` then conjoins the two scope sets with [`conjoinArbacDbScopes`](/api/arbac-moost#conjoinarbacdbscopes) — row filters via [`conjoinScopeFilters`](/api/arbac#conjoinscopefilters), controls via [`intersectControlsPolicy`](/api/arbac#intersectcontrolspolicy) — so the effective query policy is `assigned ∩ presented`, never the union.

Projections intersect by path through [`intersectProjections`](/api/arbac#restrictprojection): `{ a: 1 }` ∩ `{ "a.b": 1 }` → `{ "a.b": 1 }`. For DB controllers `useArbac().evaluate` passes the table schema, so an included parent with a child hidden on the other side (`{ a: 1 }` ∩ `{ "a.c": 0 }`) keeps exactly the other children. The result is never wider than either side. When the two projections share no field, the request matches no rows. It never falls back to the unrestricted `{}`.

Joined rows (`$with`) follow the same rule. A relation only ONE side declares a `with.<rel>` sub-scope for is conjoined with the other side's policy for it — the caller's own grant on the related table — when the request resolves it (0.1.72+). A credential that declares `with.owner: {}` through a claimed attr therefore still sees only the owners the user's own `users` grant shows; without a grant there, the relation is unknown.

Custom (declaration-merged) scope fields are conjoined only through a rule you register. An unregistered one fails the request with a generic 500 rather than being dropped. A field with a `rowFilter` is folded into each side's row filter before the conjunction. See [Custom scope fields](./scopes#custom-scope-fields).

## View as — previewing a role the user does not hold

By default a claimed role the user lacks is dropped, so an admin cannot preview what a `reader` sees. Setting `allowUnheldRoles: true` on the claims evaluates the claimed `roles` as given (since 0.1.72). The credential pass is still conjoined with the user's full authority exactly as above, so the preview can never widen beyond the user: an admin sees exactly the reader's surface, and a user narrower than the previewed role stays clipped to their own rows, fields, controls and actions. Unknown role ids are dropped silently before evaluation, so untrusted claims cannot trigger role warnings.

`extractAttenuation` never sets the flag — your `getAttenuation()` decides when a credential may use it:

```ts
override async getAttenuation() {
  const claims = extractAttenuation(AppCredential, useAuth().getAuthContext());
  // Honor "view as" only for credentials minted by an operator allowed to preview roles.
  return claims && isPreviewCredential() ? { ...claims, allowUnheldRoles: true } : claims;
}
```

It composes with [custom scope fields](./scopes#custom-scope-fields): the previewed role's custom fields are conjoined by the same registered rules.

## DOs / DON'Ts

- **DO** treat attenuation as restrict-only: claims with a role the user lacks simply drop it in the intersection — they never add it (with `allowUnheldRoles` the role is evaluated, but still clipped to the user).
- **DO** gate who may issue an `allowUnheldRoles` credential (e.g. behind a privilege) — it never widens authority, but it does reveal what another role's surface looks like within the user's own.
- **DON'T** combine user and credential scopes with `mergeScopeFilters` / `unionControlsPolicy` — those _widen_ (an empty `{}` means "unrestricted" and would erase the narrowing). The conjunction helpers read the same empty scope as "no additional restriction from this side".
- **DO** rely on fail-closed parsing: an attenuator role value that yields no usable strings (a number, `""`, an empty array) extracts to `[]` — an empty assumed-role set that denies everything, never a fallback to full authority.
- **DON'T** be surprised by `null` vs absent on narrowing attrs: a stateful store round-trips an UNSET optional column as SQL `null`, and `extractAttenuation` treats `null` and `undefined` both as ABSENT (no narrowing). Only a present, non-null value narrows. Hand-built contexts in unit tests miss this — round-trip through a real store in e2e.
- **DO** validate at boot with `validateAttenuationTargets` — a typo'd attr target should crash startup, not pass requests.

## See also

- [Scope Merging](./scopes) — the additive helpers and their restrictive counterparts.
- [Mental Model](./concepts) — deny-wins evaluation this intersects on top of.
- [`@aooth/arbac-core` API](/api/arbac-core) · [`@aooth/arbac` API](/api/arbac) · [`@aooth/arbac-moost` API](/api/arbac-moost) — exact signatures.
- [Credentials & Sessions](/auth/credentials) — per-mint `ttl` / `kind` for PAT-style tokens.
