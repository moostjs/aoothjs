// Fixtures for read-policy.integration.spec.ts — the 0.1.72 read-side
// policy: `$with` inherit-target (P1), derived columns following their
// source, atomic JSON columns on SQL adapters, `/meta` search surface.

@db.table 'rpol_orgs'
export interface PolOrg {
    @meta.id
    id: number

    name: string

    tenant: string

    budget: number
}

@db.table 'rpol_users'
export interface PolUser {
    @meta.id
    id: number

    name: string

    tenant: string

    salary: number

    @db.rel.FK
    orgId?: PolOrg.id

    @db.rel.to
    org?: PolOrg
}

@db.table 'rpol_tasks'
export interface PolTask {
    @meta.id
    id: number

    @db.index.fulltext 'task_txt'
    title: string

    @db.index.fulltext 'task_txt'
    secretNote: string

    @db.column.searchable
    tenant: string

    @db.rel.FK
    ownerId?: PolUser.id

    @db.rel.to
    owner?: PolUser

    @db.json
    settings: {
        apiKey: string
        theme: string
    }

    @db.column.derived
    apiKeyCopy: PolTask.settings.apiKey

    @db.index.geo
    home: db.geoPoint
}
