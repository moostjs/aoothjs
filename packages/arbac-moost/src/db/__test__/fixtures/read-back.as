// Fixture for insert-representation.integration.spec.ts — a table keyed by
// a composite primary key: its read-back is the `/one?…` (getOneComposite)
// read, authorized by that handler's grant.

@db.table 'read_back_pairs'
export interface RbPair {
    @meta.id
    left: number

    @meta.id
    right: number

    label: string

    secret: string
}
