/**
 * Audit event emitter — used by `LoginWorkflow.audit-login` (and future
 * recovery / invite audit steps) to fan out login.success and similar events
 * to consumer-supplied sinks (DB table, log file, Kafka topic).
 *
 * Aoothjs ships no concrete sink — register your own via
 * `setProvideRegistry([AuditEmitter, () => myEmitter])`. When not registered,
 * workflows inject `undefined` and skip emission silently.
 */

export interface AuditEvent {
  kind: string;
  /** Auth-scoped user identity (the `username` resolved by the workflow). */
  userId?: string;
  /** Workflow id that emitted the event (e.g. `auth.login`). */
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

/** No-op `AuditEmitter` used when the consumer did not register one. */
export const NoopAuditEmitter: AuditEmitter = {
  emit() {
    /* no-op */
  },
};
