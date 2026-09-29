// Fixtures for the relations / write-scope security regressions: a
// tenant-scoped task graph with TO / FROM / VIA relations, a nested object,
// a string PK next to a string unique key, and a @db.writeOnly column on the
// related users table.

@db.table 'rp_orgs'
export interface RpOrg {
    @meta.id
    id: number

    name: string

    tenant: string

    budget: number
}

@db.table 'rp_users'
export interface RpUser {
    @meta.id
    id: number

    name: string

    tenant: string

    salary: number

    @db.writeOnly
    password?: string

    @db.rel.FK
    orgId?: RpOrg.id

    @db.rel.to
    org?: RpOrg
}

@db.table 'rp_tags'
export interface RpTag {
    @meta.id
    @db.default.increment
    id: number

    name: string

    tenant: string
}

@db.table 'rp_tasks'
export interface RpTask {
    @meta.id
    id: number

    title: string

    tenant: string

    profile?: {
        name?: string
        tenant?: string
    }

    @db.rel.FK
    ownerId?: RpUser.id

    @db.rel.to
    owner?: RpUser

    @db.rel.via RpTaskTag
    tags?: RpTag[]
}

@db.table 'rp_task_tags'
export interface RpTaskTag {
    @meta.id
    @db.default.increment
    id: number

    @db.rel.FK
    taskId: RpTask.id

    @db.rel.FK
    tagId: RpTag.id
}

// String PK + a string unique key: a scalar id can name two rows.
@db.table 'rp_slugs'
export interface RpSlug {
    @meta.id
    id: string

    @db.index.unique 'rp_slug_idx'
    slug: string

    tenant: string

    title: string

    @db.column.version
    version: number
}

// FROM nested writes are opt-in in atscript-db (`@db.depth.limit` defaults
// to 0): a table that opted in to one level of nested children.
@db.table 'rp_projects'
@db.depth.limit 1
export interface RpProject {
    @meta.id
    id: number

    title: string

    tenant: string

    @db.rel.from
    notes?: RpNote[]
}

@db.table 'rp_notes'
export interface RpNote {
    @meta.id
    id: number

    body: string

    tenant: string

    @db.rel.FK
    projectId: RpProject.id
}
