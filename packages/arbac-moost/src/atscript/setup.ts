import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { createReplaceRegistry, type Moost } from "moost";

import { ArbacUserProvider } from "../user.provider";
import { AutoArbacUserProvider, type ArbacUserIdResolver } from "./auto-provider";
import { getArbacExtractSpec } from "./extract";
import { getArbacProjection } from "./projection";
import { setUserRecordFetcher, type UserRecordFetcher } from "./wooks";

/**
 * Minimal duck-typed user store: any value exposing `read(id) → record | null`.
 * Matches `@aoothjs/user`'s `UserStore` but admits test stubs and wrappers.
 */
export interface ArbacUserReader<T extends object> {
  read(userId: string): Promise<T | null>;
}

/** Subset of `AtscriptDbTable.findOne` used by ARBAC — kept loose to avoid pulling `@atscript/db` types into the public surface. */
export interface ArbacUserTable<T extends object> {
  findOne(query: {
    filter: Record<string, unknown>;
    controls?: { $select?: Record<string, 1> };
  }): Promise<T | null>;
}

export interface SetupArbacFromAtscriptOptions<T extends object> {
  // biome-ignore lint/suspicious/noExplicitAny: atscript type-args are invariant; loosen for the consumer
  userType: TAtscriptAnnotatedType<any, T>;
  /** Atscript-db table holding user records. Mutually exclusive with `store`. */
  table?: ArbacUserTable<T>;
  /** Duck-typed user store (`read(id)`). Mutually exclusive with `table`. */
  store?: ArbacUserReader<T>;
  /** Resolves the current event's subject id. Runs inside the event context. */
  getUserId: ArbacUserIdResolver;
  /** Warning sink. Defaults to `console.warn`. */
  warn?: (message: string) => void;
}

/**
 * One-call configuration for atscript-driven ARBAC.
 *
 * Validates the user type, precomputes a fetch projection covering id +
 * roles + attrs, wires a per-event memoized fetcher into `useUserRecord`,
 * and replaces `ArbacUserProvider` in the Moost DI container with an
 * `AutoArbacUserProvider` bound to the supplied type + resolver.
 *
 * Exactly one of `opts.table` / `opts.store` must be provided.
 */
export function setupArbacFromAtscript<T extends object>(
  moost: Moost,
  opts: SetupArbacFromAtscriptOptions<T>,
): void {
  const hasTable = opts.table !== undefined;
  const hasStore = opts.store !== undefined;
  if (hasTable === hasStore) {
    throw new Error(
      "setupArbacFromAtscript: provide exactly one of `table` or `store` (not both, not neither)",
    );
  }

  const warn = opts.warn ?? ((m: string) => console.warn(m));

  const spec = getArbacExtractSpec(opts.userType);
  if (!spec.userIdField) {
    throw new Error(
      "setupArbacFromAtscript: userType has no @arbac.userId or @meta.id field — annotate one to identify users",
    );
  }
  if (spec.roleFields.length === 0) {
    warn(
      "setupArbacFromAtscript: userType declares no @arbac.role fields — roles will be empty unless supplied by another channel",
    );
  }

  const userIdField = spec.userIdField;
  let fetcher: UserRecordFetcher;
  if (opts.table) {
    const table = opts.table;
    const projection = getArbacProjection(opts.userType);
    fetcher = (userId) =>
      table.findOne({
        filter: { [userIdField]: userId },
        controls: { $select: projection },
      });
  } else if (opts.store) {
    const store = opts.store;
    fetcher = (userId) => store.read(userId);
  } else {
    // Unreachable: the `hasTable !== hasStore` guard above ensures one is set.
    throw new Error("setupArbacFromAtscript: internal — neither table nor store resolved");
  }
  setUserRecordFetcher(fetcher);

  // Moost DI replaces a class with another zero-arg class. Capture
  // `userType` and `getUserId` in a per-setup subclass to satisfy that
  // contract.
  const userType = opts.userType;
  const getUserId = opts.getUserId;
  class BoundAutoArbacUserProvider extends AutoArbacUserProvider {
    constructor() {
      super(userType, getUserId);
    }
  }

  moost.setReplaceRegistry(createReplaceRegistry([ArbacUserProvider, BoundAutoArbacUserProvider]));
}
