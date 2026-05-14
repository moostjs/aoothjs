@db.table 'departments'
@db.http.path '/departments'
export interface Department {
    @meta.id
    @db.default.uuid
    id: string

    @meta.required
    @expect.maxLength 64
    @db.index.plain 'departments_tenant_idx'
    tenantId: string

    @meta.required
    @expect.maxLength 64
    name: string

    @db.default.now
    createdAt: number.timestamp
}
