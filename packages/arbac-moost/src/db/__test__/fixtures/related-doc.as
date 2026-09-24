// Fixture for hidden-columns.integration.spec.ts `$with` cases — a doc whose
// author (and the author's org) carry columns a `with` sub-scope hides:
// related paths must answer like nonexistent fields, not act as oracles.

@db.table 'rel_orgs'
export interface RelOrg {
    @meta.id
    id: number

    name: string

    budget: number
}

@db.table 'rel_authors'
export interface RelAuthor {
    @meta.id
    id: number

    name: string

    salary: number

    @db.rel.FK
    orgId: RelOrg.id

    @db.rel.to
    org?: RelOrg
}

@db.table 'rel_docs'
export interface RelDoc {
    @meta.id
    id: number

    title: string

    secret: string

    @db.rel.FK
    authorId: RelAuthor.id

    @db.rel.to
    author?: RelAuthor
}
