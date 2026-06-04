```ts:no-line-numbers
import {
  AuthCredential,
  CredentialStoreJwt,
  DenylistStoreMemory,
} from "@aooth/auth";

const auth = new AuthCredential<{ roles: string[] }>({
  store: new CredentialStoreJwt({
    algorithm: "HS256",
    secret: process.env.JWT_SECRET!,
    denylist: new DenylistStoreMemory(),
  }),
  accessTtl: 60 * 60_000,
  refresh: {
    ttl: 30 * 24 * 3600_000,
    rotation: "sliding",
    rotationGraceMs: 30_000,
    onRotationReuse: (state) => log.warn("refresh reuse", state),
  },
});

const issued = await auth.issue("alice", {
  roles: ["admin"], // typed payload field, flat
  metadata: { ip: req.ip },
});

// On every request:
const ctx = await auth.validate(issued.accessToken);
// ctx → { userId, method, credentialId, expiresAt, claims }
```
