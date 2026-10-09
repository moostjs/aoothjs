import { describe, expect, it, vi } from "vite-plus/test";
import { UserAuthError } from "./errors";
import { UserStoreMemory } from "./store/memory";
import { UserService } from "./user-service";

const FAST_SCRYPT = { scryptN: 1024, scryptR: 1, scryptP: 1, keyLength: 32 };

function setup() {
  const store = new UserStoreMemory();
  const findById = vi.spyOn(store, "findById");
  const svc = new UserService(store, { password: { ...FAST_SCRYPT } });
  return { store, svc, findById };
}

describe("UserService.getUserSnapshot", () => {
  it("shares one read per scope until a write goes through the service", async () => {
    const { svc, findById } = setup();
    const { id } = await svc.createUser("alice");
    const scope = {};
    findById.mockClear();
    const a = await svc.getUserSnapshot(id, scope);
    const b = await svc.getUserSnapshot(id, scope);
    expect(b).toBe(a);
    expect(findById).toHaveBeenCalledTimes(1);
    await svc.recordLogin(id);
    const c = await svc.getUserSnapshot(id, scope);
    expect(c.account.lastLogin).toBeGreaterThan(0);
    expect(findById).toHaveBeenCalledTimes(2); // the shared read + one fresh read after the write
  });

  it("is per scope; a write by another method (withCas) invalidates; misses are not kept", async () => {
    const { svc, findById } = setup();
    const { id } = await svc.createUser("bob");
    const s1 = {};
    const s2 = {};
    await svc.getUserSnapshot(id, s1);
    findById.mockClear();
    await svc.getUserSnapshot(id, s2);
    expect(findById).toHaveBeenCalledTimes(1);
    await svc.addMfaMethod(id, { name: "email", value: "b@x", confirmed: true });
    findById.mockClear();
    const fresh = await svc.getUserSnapshot(id, s1);
    expect(fresh.mfa.methods).toHaveLength(1);
    expect(findById).toHaveBeenCalledTimes(1);
    await expect(svc.getUserSnapshot("nope", s1)).rejects.toBeInstanceOf(UserAuthError);
    await expect(svc.getUserSnapshot("nope", s1)).rejects.toBeInstanceOf(UserAuthError);
    expect(findById).toHaveBeenCalledTimes(3);
  });

  it("a read racing a write is not served after the write", async () => {
    const { svc } = setup();
    const { id } = await svc.createUser("carol");
    const scope = {};
    const reading = svc.getUserSnapshot(id, scope); // started before the write
    await svc.lockAccount(id, "test");
    await reading;
    expect((await svc.getUserSnapshot(id, scope)).account.locked).toBe(true);
  });
});

describe("UserService.onUserWrite", () => {
  it("reports each settled write with the user id; unsubscribe stops it", async () => {
    const { svc } = setup();
    const ids: Array<string | undefined> = [];
    const off = svc.onUserWrite((id) => ids.push(id));
    const { id } = await svc.createUser("dave");
    await svc.activateAccount(id);
    await svc.addMfaMethod(id, { name: "email", value: "d@x", confirmed: false });
    await expect(svc.lockAccount("missing", "x")).rejects.toBeInstanceOf(UserAuthError);
    await svc.deleteUser(id);
    expect(ids).toEqual([id, id, id, "missing", id]);
    off();
    await svc.createUser("erin");
    expect(ids).toHaveLength(5);
  });

  it("a throwing listener never skips the others (the error still surfaces)", async () => {
    const { svc } = setup();
    const seen: Array<string | undefined> = [];
    svc.onUserWrite(() => {
      throw new Error("listener down");
    });
    svc.onUserWrite((id) => seen.push(id));
    await expect(svc.createUser("gina")).rejects.toThrow("listener down");
    expect(seen).toHaveLength(1);
  });

  it("keeps the store's own methods and identity checks working through the service", async () => {
    const { store, svc } = setup();
    const { id } = await svc.createUser("frank");
    expect(await svc.findByHandle("frank")).toMatchObject({ id });
    expect(await store.exists("frank")).toBe(true);
  });
});
