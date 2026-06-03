import { type Clock, defaultClock } from "@aooth/auth";
import { type JWTPayload, SignJWT, errors as joseErrors, jwtVerify } from "jose";
import { OAuthError } from "./errors";

/**
 * The CSRF/replay binding carried across the OAuth bounce (RFC §7). Signed into
 * a compact HS256 JWT by {@link signState} so it is tamper-evident in the URL
 * `state` param. `verifier`/`nonce` are optional: a stateless deployment puts
 * them inside the signed state; a server-side-store deployment (the RFC's
 * chosen design, §3.6) keeps them server-side and binds only `handle` here.
 */
export interface OAuthStatePayload {
  /** High-entropy anti-CSRF random; also double-submitted in a cookie (phase 3). */
  random: string;
  /** Bound provider id — a `google` state can't be replayed against `github`. */
  provider: string;
  /** Post-login app redirect target (validated as a same-origin relative path in phase 3). */
  redirect: string;
  /** PKCE code verifier — present only in the stateless mode. */
  verifier?: string;
  /** OIDC nonce — present only in the stateless mode. */
  nonce?: string;
  /** Opaque server-side wf-state handle (`wfs`) — present in the server-store mode. */
  handle?: string;
  /** Initiating user id — bound for `/link` to defeat the confused deputy (§4). */
  userId?: string;
}

export interface SignStateOptions {
  /** State lifetime in seconds. Default `600` (10 min) — OAuth round-trips are short. */
  ttlSec?: number;
  clock?: Clock;
}

export interface VerifyStateOptions {
  clock?: Clock;
}

const DEFAULT_TTL_SEC = 600;

function toKey(secret: string | Uint8Array): Uint8Array {
  return typeof secret === "string" ? new TextEncoder().encode(secret) : secret;
}

/**
 * Sign the binding into a compact HS256 JWT. Field names are abbreviated to
 * keep the URL `state` short; {@link verifyState} maps them back.
 */
export async function signState(
  payload: OAuthStatePayload,
  secret: string | Uint8Array,
  opts: SignStateOptions = {},
): Promise<string> {
  const clock = opts.clock ?? defaultClock;
  const nowSec = Math.floor(clock.now() / 1000);
  const claims: JWTPayload = {
    rnd: payload.random,
    prv: payload.provider,
    rdr: payload.redirect,
  };
  if (payload.verifier !== undefined) claims.vrf = payload.verifier;
  if (payload.nonce !== undefined) claims.non = payload.nonce;
  if (payload.handle !== undefined) claims.hdl = payload.handle;
  if (payload.userId !== undefined) claims.uid = payload.userId;

  return new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt(nowSec)
    .setExpirationTime(nowSec + (opts.ttlSec ?? DEFAULT_TTL_SEC))
    .sign(toKey(secret));
}

/**
 * Verify + decode the signed state. Pins `HS256` (rejects `alg:none` / key
 * confusion). Throws {@link OAuthError} `STATE_EXPIRED` past TTL,
 * `STATE_INVALID` on any other signature/shape failure.
 */
export async function verifyState(
  token: string,
  secret: string | Uint8Array,
  opts: VerifyStateOptions = {},
): Promise<OAuthStatePayload> {
  const clock = opts.clock ?? defaultClock;
  let payload: JWTPayload;
  try {
    const res = await jwtVerify(token, toKey(secret), {
      algorithms: ["HS256"],
      currentDate: new Date(clock.now()),
    });
    payload = res.payload;
  } catch (err) {
    if (err instanceof joseErrors.JWTExpired) throw new OAuthError("STATE_EXPIRED");
    throw new OAuthError("STATE_INVALID");
  }

  const random = payload.rnd;
  const provider = payload.prv;
  const redirect = payload.rdr;
  if (typeof random !== "string" || typeof provider !== "string" || typeof redirect !== "string") {
    throw new OAuthError("STATE_INVALID", "Malformed state payload");
  }

  const out: OAuthStatePayload = { random, provider, redirect };
  if (typeof payload.vrf === "string") out.verifier = payload.vrf;
  if (typeof payload.non === "string") out.nonce = payload.non;
  if (typeof payload.hdl === "string") out.handle = payload.hdl;
  if (typeof payload.uid === "string") out.userId = payload.uid;
  return out;
}
