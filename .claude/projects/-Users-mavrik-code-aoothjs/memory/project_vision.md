---
name: aoothjs project vision
description: High-level vision for the @aoothjs/* monorepo — unified auth+authz stack for moost/atscript ecosystem
type: project
---

@aoothjs/\* is a unified auth+authz monorepo targeting the moost/atscript ecosystem.

**Packages (final names):**

- `@aoothjs/user` (renamed from `@aoothjs/aooth`) — user credential primitives
- `@aoothjs/arbac-core` — zero-dep RBAC engine (migrated from `@prostojs/arbac`)
- `@aoothjs/arbac` — re-exports arbac-core + builder API, privilege factories, scope merge utils, codegen
- `@aoothjs/auth` — sessions, tokens, password reset, MFA flows (framework-agnostic)
- `@aoothjs/user-as` — UsersStore backed by @atscript/db, exports `user.as` model
- `@aoothjs/arbac-moost` — moost RBAC integration (migrated from `@moostjs/arbac`)
- `@aoothjs/auth-moost` — moost auth controllers, guards, composables
- `@aoothjs/atscript-plugin` — `@aooth.*` annotations (@aooth.role, @aooth.attr, @aooth.username, @aooth.password)

**Naming convention:** `<concern>-<platform>` (e.g. `arbac-moost`, `auth-moost`, `user-as`, `arbac-as`)

**Why:** Consolidate scattered auth code (prostojs/arbac, moostjs/arbac, rvmode/app-portal patterns) into one coherent stack.

**How to apply:** See TODO.md for the phased roadmap. Critical path is Phase 0→1→2→5→6.

**Key design decisions:**

- Scope merge utilities use mongo-style projections because @atscript/db uses @uniqu/core which abstracts queries that way across all DB adapters
- arbac builder uses explicit `.use()` composition, not app-portal's Proxy pattern
- Auth methods (Phase 4) designed from scratch, not ported from rvmode PoC
- atscript-plugin design driven by real integration needs (Phase 7, after auth-moost)
- Use `@meta.sensitive` from atscript (already exists) — don't duplicate with `@aooth.sensitive`
