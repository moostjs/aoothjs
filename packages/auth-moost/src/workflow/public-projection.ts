/**
 * `ctx.public` — the form-facing projection `AuthWorkflow` rebuilds before
 * every pause, in the request's language — is a per-response render value,
 * not workflow state. `WfTriggerProvider` strips it before a paused state is
 * persisted (store-backed and token-backed alike), so the state never carries
 * rendered (translated) text. Only projections built by `AuthWorkflow` are
 * stripped: an app's own `public` context key is left alone.
 */
const projections = new WeakSet<object>();

/** Marks `projection` as `AuthWorkflow`'s rendered `ctx.public`. */
export function markPublicProjection(projection: object): void {
  projections.add(projection);
}

/** `context` without its rendered `public` projection (the same object when there is none). */
export function withoutPublicProjection<T>(context: T): T {
  if (!context || typeof context !== "object") return context;
  const pub = (context as { public?: unknown }).public;
  if (!pub || typeof pub !== "object" || !projections.has(pub)) return context;
  const { public: _projection, ...rest } = context as Record<string, unknown>;
  return rest as T;
}
