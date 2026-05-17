<p align="center">
  <a href="https://aooth.moost.org">
    <img src="https://aooth.moost.org/logo.svg" alt="aoothjs" width="160" />
  </a>
</p>

<h1 align="center">aoothjs</h1>

<p align="center">
  Authentication + authorization for the <a href="https://moost.org">Moost</a> / <a href="https://atscript.moost.org">atscript</a> ecosystem.
</p>

<p align="center">
  <a href="https://aooth.moost.org"><strong>Documentation →</strong></a>
</p>

---

`@aoothjs/*` is a TypeScript monorepo covering the full auth stack: user credentials, password + MFA, sessions and tokens, RBAC, DB-backed storage, and Moost framework integration.

## Packages

| Package                                          | Purpose                                                                                     |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| [`@aoothjs/user`](./packages/user)               | User credential primitives — password hashing, MFA, lockout, policy engine                  |
| [`@aoothjs/auth`](./packages/auth)               | Session and token layer — JWT / encapsulated stores, refresh rotation, denylist             |
| [`@aoothjs/arbac-core`](./packages/arbac-core)   | Zero-dependency RBAC engine — role evaluation, scope merge                                  |
| [`@aoothjs/arbac`](./packages/arbac)             | Batteries-included RBAC — builder API, privilege factories, scope utilities                 |
| [`@aoothjs/auth-moost`](./packages/auth-moost)   | Moost integration — `AuthGuard`, `useAuth`, REST endpoints, login/recovery/invite workflows |
| [`@aoothjs/arbac-moost`](./packages/arbac-moost) | Moost RBAC integration — `@ArbacResource`, `AsArbacDbController`, atscript wiring           |

## Quick links

- **Documentation:** https://aooth.moost.org
- **Quick start:** https://aooth.moost.org/guide/quick-start
- **AI agent skill:** [`skills/aoothjs`](./skills/aoothjs)

## License

MIT
