import type { UserCredentials, UserStoreUpdate } from "../types";

export abstract class UserStore<T extends object = object> {
  abstract exists(username: string): Promise<boolean>;
  abstract findByUsername(username: string): Promise<(UserCredentials & T) | null>;
  abstract create(data: UserCredentials & T): Promise<void>;
  abstract update(username: string, update: UserStoreUpdate): Promise<boolean>;
}
