// Fixture for hidden-columns.integration.spec.ts — a table whose unique
// `code` column a scoped role cannot see: a DELETE / PATCH / PUT addressing a
// row through that key must answer exactly like a key that does not exist.

@db.table 'keyed_docs'
export interface KeyedDoc {
    @meta.id
    id: number

    @db.index.unique 'code_idx'
    code: string

    title: string

    owner: string
}
