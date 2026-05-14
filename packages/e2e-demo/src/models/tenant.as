@db.table 'tenants'
@db.http.path '/tenants'
export interface Tenant {
    @meta.id
    @db.default.uuid
    id: string

    @meta.required
    @expect.maxLength 64
    @db.index.unique 'tenants_name_unique'
    name: string

    @expect.maxLength 128
    domain?: string

    @meta.required
    @ui.form.options 'free', 'free'
    @ui.form.options 'pro', 'pro'
    @ui.form.options 'enterprise', 'enterprise'
    plan: 'free' | 'pro' | 'enterprise'

    @db.default.now
    createdAt: number.timestamp
}
