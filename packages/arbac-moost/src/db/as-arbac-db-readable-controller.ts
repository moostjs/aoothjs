import type { TProjection } from "@aooth/arbac";
import { AsDbReadableController, getDbEndpoint } from "@atscript/moost-db";
import type { TDbControlsType, TDbRequestContext } from "@atscript/moost-db";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { Inherit } from "moost";

import type { TMetaResponse } from "@atscript/db";

import { ARBAC_DELEGATED_AUTH } from "../arbac.mate";
import { applyArbacMetaOverlay } from "./meta-projection";
import { registerArbacDbTarget } from "./relation-policy";
import {
  arbacActionRowScope,
  arbacAllowedActions,
  arbacRowFilter,
  authorizeArbacForm,
  prepareArbacRequest,
  requestFieldVisible,
  requireRequestScopes,
} from "./request-scopes";
import {
  applyArbacControls,
  applyArbacProjection,
  applyArbacRelationScopes,
} from "./shared-read-helpers";

/**
 * Read-only mirror of {@link AsArbacDbController} for view-style controllers
 * built on top of `@atscript/moost-db`'s {@link AsDbReadableController}.
 * Applies the same fail-closed `prepareRequest` and filter / projection /
 * controls overlays — no write-side hooks because the parent exposes none.
 */
@Inherit()
export class AsArbacDbReadableController<
  T extends TAtscriptAnnotatedType = TAtscriptAnnotatedType,
> extends AsDbReadableController<T> {
  /** Makes this controller the `$with` policy source for its table's ARBAC resource. */
  protected readonly _arbacRelationTarget = registerArbacDbTarget(this);

  /** Same contract as {@link AsArbacDbController.prepareRequest}. */
  protected prepareRequest(ctx: TDbRequestContext): Promise<void> {
    return prepareArbacRequest(ctx, this.readable);
  }

  /** Same contract as {@link AsArbacDbController.transformFilter}. */
  protected transformFilter(filter: Record<string, unknown> | undefined): Record<string, unknown> {
    return arbacRowFilter(filter);
  }

  /** Same contract as {@link AsArbacDbController.transformProjection}. */
  protected transformProjection(projection?: TProjection): TProjection | undefined {
    return applyArbacProjection(projection, requireRequestScopes(), this.readable);
  }

  /** Same contract as {@link AsArbacDbController.validateControls}. */
  protected validateControls(
    controls: Record<string, unknown>,
    type: TDbControlsType,
  ): string | undefined {
    const baseErr = super.validateControls(controls, type);
    if (baseErr) return baseErr;

    const scopes = requireRequestScopes();
    applyArbacControls(controls, scopes);
    applyArbacRelationScopes(controls, scopes, this.readable);
    return undefined;
  }

  /** Same contract as {@link AsArbacDbController.applyMetaOverlay}. */
  protected applyMetaOverlay(meta: TMetaResponse): Promise<TMetaResponse> {
    return applyArbacMetaOverlay(meta, this.readable);
  }

  /** Same contract as {@link AsArbacDbController.authorizeForm}. */
  protected authorizeForm(_name: string, actionNames: readonly string[]): Promise<boolean> {
    return authorizeArbacForm(actionNames);
  }

  /** Same contract as {@link AsArbacDbController.actionRowScope}. */
  protected actionRowScope(name: string): Promise<Record<string, unknown> | undefined> {
    return arbacActionRowScope(name);
  }

  /** Same contract as {@link AsArbacDbController.allowedActions}. */
  protected allowedActions(names: readonly string[]): Promise<string[]> {
    return arbacAllowedActions(names);
  }

  /** Same contract as {@link AsArbacDbController.[ARBAC_DELEGATED_AUTH]}. */
  [ARBAC_DELEGATED_AUTH](method: string): boolean {
    return getDbEndpoint(this, method) !== undefined;
  }

  /** Same contract as {@link AsArbacDbController.hasField}. */
  protected hasField(path: string): boolean {
    return super.hasField(path) && requestFieldVisible(path, this.readable);
  }
}
