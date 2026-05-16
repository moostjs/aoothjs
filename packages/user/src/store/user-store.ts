import type { UserCredentials, UserStoreUpdate } from "../types";

export abstract class UserStore<T extends object = object> {
  abstract exists(username: string): Promise<boolean>;
  abstract findByUsername(username: string): Promise<(UserCredentials & T) | null>;
  abstract create(data: UserCredentials & T): Promise<void>;
  abstract update(username: string, update: UserStoreUpdate): Promise<boolean>;
  /**
   * Hard-delete the row. Returns `true` when a row was removed, `false` when
   * the username was not found. Used by `UserService.deleteUser` (and in turn
   * by the invite workflow's `auth.cancelInvite` step).
   */
  abstract delete(username: string): Promise<boolean>;
}
