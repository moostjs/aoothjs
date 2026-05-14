import { Tenant } from './tenant'

@db.table 'departments'
@db.http.path '/departments'
export interface Department {
    @meta.id
    @db.default.uuid
    id: string

    @meta.required
    @db.rel.FK
    @db.index.plain 'departments_tenant_idx'
    tenantId: Tenant.id

    @meta.required
    @expect.maxLength 64
    name: string

    @db.default.now
    createdAt: number.timestamp
}
