// Fixtures for write-scope*.integration.spec.ts — a tenant-scoped, versioned
// doc with a replace-strategy (`profile`) and a merge-strategy (`settings`)
// nested object, a TO relation (owner) and a FROM relation
// (notes, opted in to one level of nested writes), plus an action input form.

@db.table 'wr_users'
export interface WrUser {
    @meta.id
    id: number

    name: string

    tenant: string
}

@db.table 'wr_docs'
@db.depth.limit 1
export interface WrDoc {
    @meta.id
    id: number

    title: string

    tenant: string

    status?: string

    profile?: {
        name?: string
        tenant?: string
    }

    @db.patch.strategy 'merge'
    settings?: {
        theme?: string
        locked?: string
    }

    @db.column.version
    version: number

    @db.rel.FK
    ownerId?: WrUser.id

    @db.rel.to
    owner?: WrUser

    @db.rel.from
    notes?: WrNote[]
}

@db.table 'wr_notes'
export interface WrNote {
    @meta.id
    id: number

    body: string

    tenant: string

    @db.rel.FK
    docId: WrDoc.id
}

export interface WrSignForm {
    note: string
}
