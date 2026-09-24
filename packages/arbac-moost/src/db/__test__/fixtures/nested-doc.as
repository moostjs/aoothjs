// Fixture for the `$select` ∩ scope-projection integration tests — a table
// with a nested object so dotted scope paths (`a.b` / `a.c`) can be narrowed.

@db.table 'nested_docs'
export interface NestedDoc {
    @meta.id
    id: number

    title: string

    a: {
        b: string
        c: string
    }
}
