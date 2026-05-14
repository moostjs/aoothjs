@db.table 'documents'
@db.http.path '/documents'
export interface Document {
    @meta.id
    @db.default.uuid
    id: string

    @meta.required
    @db.index.plain 'documents_tenant_idx'
    tenantId: string

    @meta.required
    @expect.maxLength 200
    title: string

    @meta.required
    @ui.form.options 'public', 'public'
    @ui.form.options 'internal', 'internal'
    @ui.form.options 'confidential', 'confidential'
    classification: 'public' | 'internal' | 'confidential'

    @meta.required
    @expect.maxLength 128
    ownerUsername: string

    projectId?: string

    @expect.maxLength 65000
    body?: string

    @db.default.now
    createdAt: number.timestamp
}
