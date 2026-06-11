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

`extractAttenuation` walks the model's `@arbac.attenuate.*` annotations against the flat auth context and returns [`AoothArbacClaims`](/api/arbac-moost#aootharbacclaims) (`{ roles?, attrs? }`) — or `undefined` when no attenuator field is set, so a normal token costs nothing.

Call `validateAttenuationTargets(AppCredential, knownUserAttrKeys)` **once at boot**: it fails loud if any `@arbac.attenuate.attr` targets a key that is not a real user attribute, catching a typo'd target before it silently breaks authorization.

## Intersection, not union — the soundness boundary

Attenuation is the restrictive mirror of the additive [scope-merging helpers](./scopes), and confusing the two is the central footgun. The engine never _grants_ from a credential: with claims present, [`Arbac.evaluate`](/api/arbac-core) runs the policy **twice** — full roles, then attenuated roles — and intersects the OUTCOMES (`allowed` only if both passes allow; the attenuated scopes come back as `credScopes`). `useArbac` then conjoins the two scope sets with [`conjoinArbacDbScopes`](/api/arbac-moost#conjoinarbacdbscopes) — row filters via [`conjoinScopeFilters`](/api/arbac#conjoinscopefilters), controls via [`intersectControlsPolicy`](/api/arbac#intersectcontrolspolicy) — so the effective query policy is `assigned ∩ presented`, never the union.

## DOs / DON'Ts

- **DO** treat attenuation as restrict-only: claims with a role the user lacks simply drop it in the intersection — they never add it.
- **DON'T** combine user and credential scopes with `mergeScopeFilters` / `unionControlsPolicy` — those _widen_ (an empty `{}` means "unrestricted" and would erase the narrowing). The conjunction helpers read the same empty scope as "no additional restriction from this side".
- **DO** rely on fail-closed parsing: an attenuator role value that yields no usable strings (a number, `""`, an empty array) extracts to `[]` — an empty assumed-role set that denies everything, never a fallback to full authority.
- **DON'T** be surprised by `null` vs absent on narrowing attrs: a stateful store round-trips an UNSET optional column as SQL `null`, and `extractAttenuation` treats `null` and `undefined` both as ABSENT (no narrowing). Only a present, non-null value narrows. Hand-built contexts in unit tests miss this — round-trip through a real store in e2e.
- **DO** validate at boot with `validateAttenuationTargets` — a typo'd attr target should crash startup, not pass requests.

## See also

- [Scope Merging](./scopes) — the additive helpers and their restrictive counterparts.
- [Mental Model](./concepts) — deny-wins evaluation this intersects on top of.
- [`@aooth/arbac-core` API](/api/arbac-core) · [`@aooth/arbac` API](/api/arbac) · [`@aooth/arbac-moost` API](/api/arbac-moost) — exact signatures.
- [Credentials & Sessions](/auth/credentials) — per-mint `ttl` / `kind` for PAT-style tokens.
