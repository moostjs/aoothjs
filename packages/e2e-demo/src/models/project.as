import { Tenant } from './tenant'
import { Department } from './department'

@db.table 'projects'
@db.http.path '/projects'
export interface Project {
    @meta.id
    @db.default.uuid
    id: string

    @meta.required
    @db.rel.FK
    @db.index.plain 'projects_tenant_idx'
    tenantId: Tenant.id

    @meta.required
    @expect.maxLength 200
    name: string

    @meta.required
    @expect.maxLength 128
    ownerUsername: string

    @db.rel.FK
    departmentId?: Department.id

    @meta.required
    @ui.form.options 'public', 'public'
    @ui.form.options 'team', 'team'
    @ui.form.options 'private', 'private'
    visibility: 'public' | 'team' | 'private'

    secretBudget?: number

    @db.default.now
    createdAt: number.timestamp
}
