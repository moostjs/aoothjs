import { generateKeyPair } from "jose";
import { describe, expect, it } from "vite-plus/test";
import { CredentialStoreEncapsulated } from "../stores/encapsulated";
import { CredentialStoreJwt } from "../stores/jwt";
import { CredentialStoreMemory } from "../stores/memory";
import { AuthCredential } from "./auth-credential";

const JWT_SECRET = "this-is-a-test-secret-of-sufficient-length-1234567890";
const ENC_SECRET = "encapsulated-test-secret-1234567890abcdef";

describe("AuthCredential.deriveStateKey", () => {
  describe("JWT-HMAC store", () => {
    it("returns a 32-byte Buffer", () => {
      const auth = new AuthCredential({ store: new CredentialStoreJwt({ secret: JWT_SECRET }) });
      const key = auth.deriveStateKey();
      expect(Buffer.isBuffer(key)).toBe(true);
      expect(key.length).toBe(32);
    });

    it("is byte-identical across two separate instances for the same secret + label", () => {
      // WHY: the derived key must be STABLE across process restarts. The whole
      // point is reusing the auth secret to encrypt encapsulated wf-state
      // tokens; if the key changed per-instance, every token issued before a
      // restart would become undecryptable.
      const a = new AuthCredential({ store: new CredentialStoreJwt({ secret: JWT_SECRET }) });
      const b = new AuthCredential({ store: new CredentialStoreJwt({ secret: JWT_SECRET }) });
      expect(a.deriveStateKey().equals(b.deriveStateKey())).toBe(true);
    });

    it("returns different keys for different labels", () => {
      // WHY: domain separation — distinct subsystems must get distinct keys so
      // leaking/rotating one never compromises another sharing the secret.
      const auth = new AuthCredential({ store: new CredentialStoreJwt({ secret: JWT_SECRET }) });
      expect(auth.deriveStateKey("wf-state").equals(auth.deriveStateKey("other"))).toBe(false);
    });

    it("does NOT return the raw signing secret bytes", () => {
      // WHY: HKDF separation — the raw signing secret must never leave the
      // store; callers only ever receive a domain-separated derivative.
      const auth = new AuthCredential({ store: new CredentialStoreJwt({ secret: JWT_SECRET }) });
      const raw = new TextEncoder().encode(JWT_SECRET);
      const key = auth.deriveStateKey();
      expect(key.equals(Buffer.from(raw.subarray(0, key.length)))).toBe(false);
    });
  });

  describe("Encapsulated store", () => {
    it("returns a 32-byte Buffer, stable across instances", () => {
      // WHY: same stability contract as the JWT path — encapsulated wf-state
      // tokens encrypted with this key must survive a restart.
      const a = new AuthCredential({
        store: new CredentialStoreEncapsulated({ secret: ENC_SECRET }),
      });
      const b = new AuthCredential({
        store: new CredentialStoreEncapsulated({ secret: ENC_SECRET }),
      });
      const key = a.deriveStateKey();
      expect(Buffer.isBuffer(key)).toBe(true);
      expect(key.length).toBe(32);
      expect(key.equals(b.deriveStateKey())).toBe(true);
    });

    it("returns different keys for different labels", () => {
      // WHY: domain separation, as for the JWT store.
      const auth = new AuthCredential({
        store: new CredentialStoreEncapsulated({ secret: ENC_SECRET }),
      });
      expect(auth.deriveStateKey("wf-state").equals(auth.deriveStateKey("other"))).toBe(false);
    });
  });

  describe("Memory store (no secret)", () => {
    it("throws INVALID_CONFIG", () => {
      // WHY: stateful stores hold no reusable symmetric secret, so there is
      // nothing to derive from — the caller must supply an explicit secret
      // rather than silently get a bogus key.
      const auth = new AuthCredential({ store: new CredentialStoreMemory() });
      expect(() => auth.deriveStateKey()).toThrow();
      try {
        auth.deriveStateKey();
      } catch (e) {
        expect(e).toMatchObject({ name: "AuthError", type: "INVALID_CONFIG" });
      }
    });
  });

  describe("Asymmetric JWT store", () => {
    it("throws INVALID_CONFIG (no shareable symmetric secret)", async () => {
      // WHY: an asymmetric (ES*/RS*/EdDSA) JWT store has no symmetric secret to
      // domain-separate from; reusing the private key as IKM would be a
      // category error. Callers must provide an explicit wfStateSecret instead.
      const { privateKey, publicKey } = await generateKeyPair("ES256");
      const auth = new AuthCredential({
        store: new CredentialStoreJwt({ algorithm: "ES256", privateKey, publicKey }),
      });
      expect(() => auth.deriveStateKey()).toThrow();
      try {
        auth.deriveStateKey();
      } catch (e) {
        expect(e).toMatchObject({ name: "AuthError", type: "INVALID_CONFIG" });
      }
    });
  });
});
