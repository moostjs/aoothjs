import type { AuthWfCtx } from "./auth-workflow.ctx";

/**
 * The latest moment (ms since epoch) a pause of the run with this context may
 * live, or `undefined` for no bound: `ctx.expiresBy` when set, else — for an
 * invite accept past its password — the link's own expiry
 * (`ctx.admin.linkExpiresAt`), which also bounds runs that set the password
 * before `expiresBy` was recorded. `WfTriggerProvider` caps every pause by it.
 */
export function runExpiresBy(context: unknown): number | undefined {
  const ctx = context as AuthWfCtx | undefined;
  const cap =
    ctx?.expiresBy ?? (ctx?.accept && ctx.passwordChanged ? ctx.admin?.linkExpiresAt : undefined);
  return typeof cap === "number" && Number.isFinite(cap) && cap > 0 ? cap : undefined;
}
