import { UserAuthError } from "../errors";
import type { UserCredentials, UserStoreUpdate } from "../types";
import { UserStore } from "./user-store";
import { deepMerge, incrementAtPath } from "../utils";

export class UserStoreMemory<T extends object = object> extends UserStore<T> {
  private store = new Map<string, UserCredentials & T>();

  constructor(seed?: Record<string, UserCredentials & T>) {
    super();
    if (seed) {
      for (const [key, value] of Object.entries(seed)) {
        this.store.set(key, structuredClone(value));
      }
    }
  }

  async exists(username: string): Promise<boolean> {
    return this.store.has(username);
  }

  async findByUsername(username: string): Promise<(UserCredentials & T) | null> {
    const user = this.store.get(username);
    return user ? structuredClone(user) : null;
  }

  async create(data: UserCredentials & T): Promise<void> {
    if (this.store.has(data.username)) {
      throw new UserAuthError("ALREADY_EXISTS", `User "${data.username}" already exists`);
    }
    // OCC counter is server-managed: seed unconditionally, ignore caller-supplied version.
    const cloned = structuredClone(data);
    cloned.version = 0;
    this.store.set(data.username, cloned);
  }

  async update(username: string, update: UserStoreUpdate): Promise<boolean> {
    const user = this.store.get(username);
    if (!user) return false;
    if (update.expectedVersion !== undefined && (user.version ?? 0) !== update.expectedVersion) {
      return false;
    }
    if (update.set) {
      deepMerge(user, update.set as Record<string, unknown>);
    }
    if (update.inc) {
      for (const [path, amount] of Object.entries(update.inc)) {
        incrementAtPath(user, path, amount);
      }
    }
    user.version = (user.version ?? 0) + 1;
    return true;
  }

  async delete(username: string): Promise<boolean> {
    return this.store.delete(username);
  }
}
