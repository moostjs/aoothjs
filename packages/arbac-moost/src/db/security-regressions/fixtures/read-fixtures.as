// Fixtures for security-regressions/reads-*.spec.ts — the read-side seals over
// atscript-db features: derived columns, @db.json columns, full-text search
// (native index + @db.column.searchable fallback), geo, buckets, views (joins,
// join aliases, views over views) and @db.writeOnly.

@db.table 'read_depts'
export interface ReadDept {
    @meta.id
    id: number

    @db.column.searchable
    name: string

    budget: number

    @db.column.searchable
    secretCode: string

    @db.column.version
    rowVersion: number
}

@db.table 'read_accounts'
export interface ReadAccount {
    @meta.id
    id: number

    owner: string

    @db.column.searchable
    status: string

    @db.index.fulltext 'txt_idx'
    title: string

    @db.index.fulltext 'txt_idx'
    secretNote: string

    salary: number

    hiredAt: number.timestamp

    @db.rel.FK
    deptId: ReadDept.id

    @db.rel.to
    dept?: ReadDept

    managerId?: number

    @db.writeOnly
    pin?: string

    @db.json
    settings: {
        apiKey: string
        theme: string
        public: string
    }

    @db.column.derived
    apiKeyCopy: ReadAccount.settings.apiKey

    @db.column.derived
    themeCopy: ReadAccount.settings.theme

    @db.index.geo
    home: db.geoPoint
}

// A view joining a table the view principal may have no grant on, reading a
// JSON leaf and a write-only field.
@db.view 'read_account_view'
@db.view.for ReadAccount
@db.view.joins ReadDept, `ReadDept.id = ReadAccount.deptId`
export interface ReadAccountView {
    id: ReadAccount.id
    title: ReadAccount.title
    salary: ReadAccount.salary
    deptName: ReadDept.name
    deptBudget: ReadDept.budget
    leafKey: ReadAccount.settings.apiKey
    pin?: ReadAccount.pin
}

// Self-join through a join alias.
@db.alias ReadAccount
export type ReadManager = ReadAccount

@db.view 'read_staff'
@db.view.for ReadAccount
@db.view.joins ReadManager, `ReadManager.id = ReadAccount.managerId`, 'left'
export interface ReadStaff {
    id: ReadAccount.id
    title: ReadAccount.title
    managerTitle?: ReadManager.title
    managerSalary?: ReadManager.salary
}

// View over a view.
@db.view 'read_view_over_view'
@db.view.for ReadAccountView
export interface ReadViewOverView {
    id: ReadAccountView.id
    deptBudget: ReadAccountView.deptBudget
    leafKey: ReadAccountView.leafKey
}
