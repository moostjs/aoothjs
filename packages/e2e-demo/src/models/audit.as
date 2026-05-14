@db.table 'audit_log'
@db.http.path '/audit'
export interface AuditEntry {
    @meta.id
    @db.default.uuid
    id: string

    @meta.required
    @db.index.plain 'audit_tenant_idx'
    tenantId: string

    @meta.required
    @expect.maxLength 128
    actor: string

    @meta.required
    @expect.maxLength 64
    action: string

    @meta.required
    @expect.maxLength 64
    resource: string

    recordId?: string

    @expect.maxLength 8000
    payload?: string

    @db.default.now
    createdAt: number.timestamp
}
