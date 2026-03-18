import { type AtscriptDbTable, DbError } from "@atscript/db";
import type { UserCredentials, UserStoreUpdate } from "@aoothjs/user";
import { UserStore, UserAuthError, setAtPath } from "@aoothjs/user";

export class UserStoreAs<T extends object = object> extends UserStore<T> {
  constructor(protected table: AtscriptDbTable) {
    super();
  }

  async exists(username: string): Promise<boolean> {
    const count = await this.table.count({ filter: { username } });
    return count > 0;
  }

  async findByUsername(username: string): Promise<(UserCredentials & T) | null> {
    const result = await this.table.findOne({ filter: { username } });
    return (result as (UserCredentials & T) | null) ?? null;
  }

  async create(data: UserCredentials & T): Promise<void> {
    try {
      await this.table.insertOne(data as Record<string, unknown>);
    } catch (e: unknown) {
      if (e instanceof DbError && e.code === "CONFLICT") {
        throw new UserAuthError("ALREADY_EXISTS", `User "${data.username}" already exists`);
      }
      throw e;
    }
  }

  async update(username: string, update: UserStoreUpdate): Promise<boolean> {
    const patch: Record<string, unknown> = { username };

    if (update.set) {
      Object.assign(patch, update.set);
    }

    if (update.inc) {
      for (const [path, amount] of Object.entries(update.inc)) {
        setAtPath(patch, path, { $inc: amount });
      }
    }

    // If only username was set (no actual changes), no-op
    if (Object.keys(patch).length <= 1) return true;

    const result = await this.table.updateOne(patch as any);
    return result.matchedCount > 0;
  }
}
