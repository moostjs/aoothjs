// Fixtures for the round-13 overlay specs: `ui.valueHelp` bindings and `ref`s on
// array elements, union members, wildcard props, type aliases and JSON columns;
// a value-help bound interface; two relations to one table.

@db.table 'r13_dicts'
export interface R13Dict {
    @meta.id
    id: number
    code: string
    secretCode: string
}

@ui.valueHelp R13Dict, 'code'
export type R13Code = string

@db.table 'r13_items'
export interface R13Item {
    @meta.id
    id: number
    title: string
    codes?: R13Code[]
    one?: R13Code
    either?: R13Code | number
    refs?: R13Dict.code[]
    @ui.valueHelp R13Dict, 'secretCode'
    arrBound?: string[]
    @db.json
    bag?: {
        @ui.valueHelp R13Dict, 'code'
        [*]: string
    }
    @db.json
    snap?: R13Dict
}

export interface R13Form {
    codes?: R13Code[]
    either?: R13Code | number
    refs?: R13Dict.code[]
    bag?: {
        @ui.valueHelp R13Dict, 'code'
        [*]: string
    }
    note: string
}

export interface R13VDict {
    @meta.id
    id: number
    label: string
    @ui.valueHelp R13Dict, 'code'
    bound?: string
    chained?: R13Dict.code
}

@db.table 'r13_bound'
export interface R13Bound {
    @meta.id
    id: number
    @ui.valueHelp R13VDict, 'label'
    toVh?: string
}

@db.table 'r13_orgs'
export interface R13Org {
    @meta.id
    id: number
    name: string
}

@db.table 'r13_users'
export interface R13User {
    @meta.id
    id: number
    name: string
    @db.rel.FK
    orgId?: R13Org.id
    @db.rel.to
    org?: R13Org
}

@db.table 'r13_tasks'
export interface R13Task {
    @meta.id
    id: number
    title: string
    @db.rel.FK 'author'
    authorId?: R13User.id
    @db.rel.FK 'editor'
    editorId?: R13User.id
    @db.rel.to 'author'
    author?: R13User
    @db.rel.to 'editor'
    editor?: R13User
}
