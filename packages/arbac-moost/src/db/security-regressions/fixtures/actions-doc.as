// Fixture for actions-scope.spec.ts — a table with an owner (row scope),
// a status (gate state) and a secret (column hidden by the scope projection),
// plus an input form served by `/meta/form/:name`.

@db.table 'act_docs'
export interface ActDoc {
    @meta.id
    id: number

    owner: string

    status: string

    secret: string
}

export interface ApproveForm {
    note: string
}
