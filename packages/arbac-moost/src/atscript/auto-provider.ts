import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";

import { ArbacUserProvider } from "../user.provider";
import { extractArbacAttrs, extractArbacRoles } from "./extract";
import { useUserRecord } from "./wooks";

/** Resolver for the current event's subject id. */
export type ArbacUserIdResolver = () => string | Promise<string>;

/**
 * Auto-wired `ArbacUserProvider` bound to a `.as` user type. Reads the
 * record via the per-event `useUserRecord` wook (one fetch per event),
 * then extracts roles and attrs via the per-type cached spec.
 */
export class AutoArbacUserProvider extends ArbacUserProvider {
  constructor(
    private readonly userType: TAtscriptAnnotatedType,
    private readonly userIdResolver: ArbacUserIdResolver,
  ) {
    super();
  }

  override getUserId(): string | Promise<string> {
    return this.userIdResolver();
  }

  override async getRoles(id: string): Promise<string[]> {
    const record = await useUserRecord().get(id);
    if (record === null) return [];
    return extractArbacRoles(record as object, this.userType);
  }

  override async getAttrs(id: string): Promise<Record<string, unknown>> {
    const record = await useUserRecord().get(id);
    if (record === null) return {};
    return extractArbacAttrs(record as object, this.userType);
  }
}
