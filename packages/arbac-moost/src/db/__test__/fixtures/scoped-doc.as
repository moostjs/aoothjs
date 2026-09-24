// Fixture for hidden-columns.integration.spec.ts — a real table whose
// `secret` / `rank` columns a projection-scoped role must not be able to
// reference anywhere in a query (filter, sort, select, group, aggregate).

@db.table 'scoped_docs'
export interface ScopedDoc {
    @meta.id
    id: number

    title: string

    status: string

    secret: string

    rank: number
}
