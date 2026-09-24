import type { TProjection } from "@aooth/arbac";
import { AsDbReadableController } from "@atscript/moost-db";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { Inherit } from "moost";

import type { TMetaResponse } from "@atscript/db";

import {
  applyArbacMetaOverlay,
  isScopedFieldVisible,
  metaAlwaysVisibleFields,
} from "./meta-projection";
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

  /**
   * Same ARBAC `/meta` overlay as the writable controller (actions/crud
   * filtering + BUG-3 field-surface pruning by the read scopes' projection
   * union) — view-style metas leak hidden field names identically.
   */
  protected applyMetaOverlay(meta: TMetaResponse): Promise<TMetaResponse> {
    return applyArbacMetaOverlay(meta, metaAlwaysVisibleFields(this, this.readable));
  }

  /**
   * Scope-aware field visibility — same contract as
   * {@link AsArbacDbController.hasField}.
   */
  protected hasField(path: string): boolean {
    return (
      super.hasField(path) &&
      isScopedFieldVisible(readCachedScopes(), path, metaAlwaysVisibleFields(this, this.readable))
    );
  }
}
