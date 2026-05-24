/**
 * Audit event emitter — used by `LoginWorkflow.audit-login` (and future
 * recovery / invite audit steps) to fan out login.success and similar events
 * to consumer-supplied sinks (DB table, log file, Kafka topic).
 *
 * Aoothjs ships no concrete sink. Workflow subclasses override the
 * `audit(event)` protected method to wire their preferred sink; when not
 * overridden the workflow's default implementation is a no-op.
 */

export interface AuditEvent {
  kind: string;
  /** Auth-scoped user identity (the `username` resolved by the workflow). */
  userId?: string;
  /** Workflow id that emitted the event (e.g. `auth/login/flow`). */
  workflow?: string;
  /** Source IP (when the workflow could resolve one). */
  ip?: string;
  /** User-agent header. */
  userAgent?: string;
  /** Free-form payload — `method`, `tenantId`, etc. */
  [key: string]: unknown;
}

export interface AuditEmitter {
  emit(event: AuditEvent): Promise<void> | void;
}
