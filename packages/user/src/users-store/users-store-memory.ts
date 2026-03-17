import type { TCumulativeChanges, TAoothUserCredentials } from "../types";
import { UsersStore } from "./users-store";
import { setValue } from "../utils/get-set";

export class UsersStoreMemory<T extends object = { id: string }> extends UsersStore<T> {
  constructor(protected _store: Record<string, TAoothUserCredentials & T> = {}) {
    super();
  }

  exists(username: string) {
    return Promise.resolve(!!this._store[username]);
  }

  async read(username: string): Promise<TAoothUserCredentials & T> {
    const user = this._store[username];
    if (user) {
      return structuredClone(user);
    }
    throw new Error("Not found");
  }

  async change(username: string, changes: TCumulativeChanges) {
    const user = this._store[username];
    if (user) {
      for (const [key, values] of Object.entries(changes)) {
        setValue(user, key, values.value, values.op);
      }
      return;
    }
    throw new Error("Not found");
  }

  async create(data: TAoothUserCredentials & T) {
    if (this._store[data.username]) {
      throw new Error(`User with id "${data.username}" already exists.`);
    }
    this._store[data.username] = data;
  }
}
