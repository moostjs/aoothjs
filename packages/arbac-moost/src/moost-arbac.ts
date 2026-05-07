import { Arbac } from "@aoothjs/arbac-core";
import { Injectable } from "moost";

/**
 * A DI-enabled extension of the `Arbac` class for use within Moost.
 *
 * Allows ARBAC (Advanced Role-Based Access Control) to be injected into
 * Moost services and controllers via the framework's dependency-injection
 * container. Defaults to the SINGLETON scope so all handlers share one
 * registry of roles/resources.
 *
 * @template TUserAttrs - The type representing user attributes relevant to access control.
 * @template TScope - The type representing access control scopes.
 */
@Injectable()
export class MoostArbac<TUserAttrs extends object, TScope extends object> extends Arbac<
  TUserAttrs,
  TScope
> {}
