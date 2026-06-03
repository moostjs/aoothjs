import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { OAuthError } from "./errors";
import { type OAuthStatePayload, signState, verifyState } from "./state";

const SECRET = "test-state-secret-test-state-secret-1234"; // ≥32 chars
const SECRET_BYTES = new TextEncoder().encode(SECRET);
const at = (ms: number) => ({ now: () => ms });

const full: OAuthStatePayload = {
  random: "rnd-123",
  provider: "google",
  redirect: "/dashboard",
  verifier: "pkce-verifier",
  nonce: "nonce-abc",
  handle: "wfs-handle",
  userId: "user-9",
};

describe("signState / verifyState", () => {
  it("round-trips the full payload", async () => {
    const token = await signState(full, SECRET, { clock: at(0) });
    expect(await verifyState(token, SECRET, { clock: at(0) })).toEqual(full);
  });

  it("round-trips a minimal payload, omitting absent optional fields", async () => {
    const min: OAuthStatePayload = { random: "r", provider: "p", redirect: "/" };
    const token = await signState(min, SECRET, { clock: at(0) });
    const out = await verifyState(token, SECRET, { clock: at(0) });
    expect(out).toEqual(min);
    expect(out).not.toHaveProperty("verifier");
    expect(out).not.toHaveProperty("nonce");
    expect(out).not.toHaveProperty("userId");
  });

  it("rejects a tampered token with STATE_INVALID", async () => {
    const token = await signState(full, SECRET, { clock: at(0) });
    const tampered = `${token.slice(0, -3)}xxx`;
    await expect(verifyState(tampered, SECRET, { clock: at(0) })).rejects.toMatchObject({
      name: "OAuthError",
      type: "STATE_INVALID",
    });
  });

  it("rejects a wrong-secret signature with STATE_INVALID", async () => {
    const token = await signState(full, SECRET, { clock: at(0) });
    await expect(verifyState(token, "a-different-secret-aaaaaaaaaaaaaaaaaa")).rejects.toMatchObject(
      {
        type: "STATE_INVALID",
      },
    );
  });

  it("rejects an expired token with STATE_EXPIRED", async () => {
    const token = await signState(full, SECRET, { ttlSec: 600, clock: at(0) });
    await expect(verifyState(token, SECRET, { clock: at(601_000) })).rejects.toMatchObject({
      type: "STATE_EXPIRED",
    });
  });

  it("accepts a token still inside its TTL", async () => {
    const token = await signState(full, SECRET, { ttlSec: 600, clock: at(0) });
    await expect(verifyState(token, SECRET, { clock: at(599_000) })).resolves.toMatchObject({
      provider: "google",
    });
  });

  it("pins HS256 — a token signed with a different alg is STATE_INVALID", async () => {
    const hs512 = await new SignJWT({ rnd: "r", prv: "p", rdr: "/" })
      .setProtectedHeader({ alg: "HS512" })
      .setIssuedAt(0)
      .setExpirationTime(600)
      .sign(SECRET_BYTES);
    await expect(verifyState(hs512, SECRET, { clock: at(0) })).rejects.toMatchObject({
      type: "STATE_INVALID",
    });
  });

  it("rejects a validly-signed but malformed payload (missing random)", async () => {
    const token = await new SignJWT({ prv: "p", rdr: "/" }) // no rnd
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt(0)
      .setExpirationTime(600)
      .sign(SECRET_BYTES);
    await expect(verifyState(token, SECRET, { clock: at(0) })).rejects.toBeInstanceOf(OAuthError);
    await expect(verifyState(token, SECRET, { clock: at(0) })).rejects.toMatchObject({
      type: "STATE_INVALID",
    });
  });
});
