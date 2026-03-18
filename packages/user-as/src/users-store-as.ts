import { type AtscriptDbTable, DbError } from "@atscript/db";
import type { TAoothUserCredentials, TCumulativeChanges } from "@aoothjs/user";
import { UsersStore } from "@aoothjs/user";
import { translateChanges } from "./change-translator";

export class UsersStoreAs<T extends object = { id: string }> extends UsersStore<T> {
  constructor(protected table: AtscriptDbTable) {
    super();
  }

  async exists(username: string): Promise<boolean> {
    const count = await this.table.count({ filter: { username } });
    return count > 0;
  }

  async read(username: string): Promise<TAoothUserCredentials & T> {
    const result = await this.table.findOne({ filter: { username } });
    if (!result) {
      throw new Error("Not found");
    }
    return result as TAoothUserCredentials & T;
  }

  async create(data: TAoothUserCredentials & T): Promise<void> {
    try {
      await this.table.insertOne(data as Record<string, unknown>);
    } catch (e: unknown) {
      if (e instanceof DbError && e.code === "CONFLICT") {
        throw new Error(`User with id "${data.username}" already exists.`);
      }
      throw e;
    }
  }

  async change(username: string, changes: TCumulativeChanges): Promise<void> {
    const patch = translateChanges(changes);
    if (!patch) return;

    patch.username = username;
    const result = await this.table.updateOne(patch as any);
    if (result.matchedCount === 0) {
      throw new Error("Not found");
    }
  }
}
