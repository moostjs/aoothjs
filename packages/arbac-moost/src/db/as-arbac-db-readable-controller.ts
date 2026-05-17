import type { TProjection } from "@aoothjs/arbac";
import { AsDbReadableController } from "@atscript/moost-db";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { Inherit } from "moost";

import {
  applyArbacControls,
  applyArbacProjection,
  applyArbacRelationScopes,
  readCachedScopes,
  transformArbacFilter,
} from "./shared-read-helpers";

/**
 * Read-only mirror of {@link AsArbacDbController} for view-style controllers
 * built on top of `@atscript/moost-db`'s {@link AsDbReadableController}.
 * Applies the same filter / projection / controls overlays — no write-side
 * hooks because the parent exposes none.
 */
@Inherit()
export class AsArbacDbReadableController<
  T extends TAtscriptAnnotatedType = TAtscriptAnnotatedType,
> extends AsDbReadableController<T> {
  protected transformFilter(
    filter: Record<string, unknown> | undefined,
  ): Promise<Record<string, unknown>> {
    return transformArbacFilter(filter);
  }

  protected transformProjection(
    projection?: TProjection,
  ): TProjection | undefined | Promise<TProjection | undefined> {
    return applyArbacProjection(projection, readCachedScopes());
  }

  protected validateControls(
    controls: Record<string, unknown>,
    type: "query" | "pages" | "getOne",
  ): string | undefined {
    const baseErr = super.validateControls(controls, type);
    if (baseErr) return baseErr;

    const scopes = readCachedScopes();
    applyArbacControls(controls, scopes);
    applyArbacRelationScopes(controls, scopes);
    return undefined;
  }
}
