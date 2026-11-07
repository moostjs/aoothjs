import { RateLimitStoreMemory } from "@aooth/auth";
import { describe, expect, it } from "vite-plus/test";

import type { AuthWorkflowOpts } from "../workflow/auth-workflow.opts";
import { prepareFlowApp } from "./flow-utils";

// S5 (W6): the lock message must not reveal which handles exist.

async function messagesFor(
  lockoutDisclosure: AuthWorkflowOpts["lockoutDisclosure"],
  handle: "alice" | "ghost",
  attempts: number,
): Promise<string[]> {
  const app = await prepareFlowApp({
    userConfig: { lockout: { threshold: 3, duration: 60_000 } },
    workflowOpts: {
      ...(lockoutDisclosure && { lockoutDisclosure }),
      lockoutShadowStore: new RateLimitStoreMemory(),
    },
  });
  await app.seedUser("alice", "Password123!");
  const out: string[] = [];
  for (let i = 0; i < attempts; i++) {
    const res = await app.login(handle, "wrong-password");
    out.push(res.body.inputRequired.context.errors.__form);
  }
  return out;
}

const INVALID = "Invalid credentials";
const LOCKED = "Account locked, please try again later";

// Each sign-in hashes a password (scrypt): generous timeouts for a loaded machine.
describe("lockoutDisclosure", { timeout: 30_000 }, () => {
  it("'uniform' (default): an unknown handle locks after the same number of failures", async () => {
    const real = await messagesFor(undefined, "alice", 5);
    const unknown = await messagesFor(undefined, "ghost", 5);
    expect(real).toEqual([INVALID, INVALID, INVALID, LOCKED, LOCKED]);
    expect(unknown).toEqual(real);
  });

  it("'generic': a locked account reads like any failure", async () => {
    expect(await messagesFor("generic", "alice", 5)).toEqual(Array(5).fill(INVALID));
  });

  it("'reveal': only real accounts read as locked", async () => {
    expect(await messagesFor("reveal", "alice", 4)).toEqual([INVALID, INVALID, INVALID, LOCKED]);
    expect(await messagesFor("reveal", "ghost", 4)).toEqual(Array(4).fill(INVALID));
  });
});

/**
 * Everything a client sees of each of `threshold + 3` failed sign-ins for
 * `handle` (default `'uniform'` disclosure): status, the form it lands on, the
 * error code (if any) and the form context — messages included.
 */
async function responses(handle: "alice" | "ghost", threshold: number): Promise<unknown[]> {
  const app = await prepareFlowApp({
    userConfig: { lockout: { threshold, duration: 60_000 } },
    workflowOpts: { lockoutShadowStore: new RateLimitStoreMemory() },
  });
  await app.seedUser("alice", "Password123!");
  const out: unknown[] = [];
  for (let i = 0; i < threshold + 3; i++) {
    const res = await app.login(handle, "wrong-password");
    const body = res.body as {
      code?: string;
      inputRequired?: { payload?: { id?: string }; context?: unknown };
    };
    out.push({
      status: res.status,
      code: body.code,
      form: body.inputRequired?.payload?.id,
      context: body.inputRequired?.context,
    });
  }
  return out;
}

describe("lockoutDisclosure 'uniform' — property: unknown ≡ real", { timeout: 60_000 }, () => {
  it.each([1, 2, 3, 5])(
    "threshold %i: an unknown handle answers threshold + 3 attempts exactly like a real account",
    async (threshold) => {
      const real = await responses("alice", threshold);
      // The real account does lock within the window (the property is not vacuous).
      expect(JSON.stringify(real.at(-1))).toContain(LOCKED);
      expect(await responses("ghost", threshold)).toEqual(real);
    },
  );
});

async function sequence(handle: string): Promise<string[]> {
  // One injected clock for the account lock and the shadow store: with the
  // wall clock, a slow machine let the 300 ms lock lapse between attempts.
  let now = 1_700_000_000_000;
  const clock = () => now;
  const app = await prepareFlowApp({
    userConfig: { lockout: { threshold: 3, duration: 300 }, clock },
    workflowOpts: { lockoutShadowStore: new RateLimitStoreMemory({ clock: { now: clock } }) },
  });
  await app.seedUser("alice", "Password123!");
  const attempt = async () => {
    const res = await app.login(handle, "wrong-password");
    return res.body.inputRequired.context.errors.__form as string;
  };
  const out: string[] = [];
  for (let i = 0; i < 4; i++) out.push(await attempt());
  now += 400; // the lock expires
  for (let i = 0; i < 3; i++) out.push(await attempt());
  return out;
}

describe(
  "lockoutDisclosure 'uniform' — exact mirror and bounded store (H4/M1)",
  { timeout: 30_000 },
  () => {
    it("an unknown handle reads exactly like a real account after its lock expires", async () => {
      const real = await sequence("alice");
      expect(real).toEqual([INVALID, INVALID, INVALID, LOCKED, INVALID, LOCKED, LOCKED]);
      expect(await sequence("ghost")).toEqual(real);
    });

    it("keys are fixed-size hashes and an oversized handle never reaches the store", async () => {
      const keys: string[] = [];
      class Spy extends RateLimitStoreMemory {
        override async hit(key: string, ttl: number) {
          keys.push(key);
          return super.hit(key, ttl);
        }
      }
      const app = await prepareFlowApp({
        userConfig: { lockout: { threshold: 5, duration: 60_000 } },
        workflowOpts: { lockoutShadowStore: new Spy() },
      });
      const login = async (username: string) => {
        return app.login(username, "p");
      };
      const huge = await login("x".repeat(64 * 1024));
      expect(huge.body.inputRequired.context.errors.username).toBeTruthy();
      expect(keys).toEqual([]);
      await login("y".repeat(256));
      expect(keys).toHaveLength(1);
      expect(keys[0].length).toBeLessThan(64);
    });

    it("RateLimitStoreMemory({ maxEntries }) bounds the counters it keeps", async () => {
      const store = new RateLimitStoreMemory({ maxEntries: 3 });
      for (const k of ["a", "b", "c", "d", "e"]) await store.hit(k, 60_000);
      expect(await store.get("a")).toBe(0);
      expect(await store.get("b")).toBe(0);
      expect(await store.get("e")).toBe(1);
      await store.expire("c", 60_000); // touched → evicted last
      await store.hit("f", 60_000);
      expect(await store.get("c")).toBe(1);
      expect(await store.get("d")).toBe(0);
    });
  },
);
