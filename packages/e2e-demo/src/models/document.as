import { Tenant } from './tenant'
import { Project } from './project'

@db.table 'documents'
@db.http.path '/documents'
export interface Document {
    @meta.id
    @db.default.uuid
    id: string

    @meta.required
    @db.rel.FK
    @db.index.plain 'documents_tenant_idx'
    tenantId: Tenant.id

    @meta.required
    @expect.maxLength 200
    title: string

    @ui.form.options 'public', 'public'
    @ui.form.options 'internal', 'internal'
    @ui.form.options 'confidential', 'confidential'
    classification: 'public' | 'internal' | 'confidential'

    @meta.required
    @expect.maxLength 128
    ownerUsername: string

    @db.rel.FK
    projectId?: Project.id

    @expect.maxLength 65000
    body?: string

    @db.default.now
    createdAt: number.timestamp
}
