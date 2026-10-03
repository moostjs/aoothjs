// Fixtures for the row-action regressions of moost-db 0.1.147 (candidate-aware
// actionRowScope, view-delegated actions, query targets) and the relational
// filter predicates: issues belong to a ticket (whose team owns them) and
// carry a region (the ARBAC grant column); the board is a view over issues
// joined with their tickets.

@db.table 'ia_teams'
export interface IaTeam {
    @meta.id
    id: string

    name: string
}

@db.table 'ia_tickets'
export interface IaTicket {
    @meta.id
    key: string

    @db.rel.FK
    teamId: IaTeam.id

    status: string

    // Not opted in to client relational predicates (server scopes may still use it).
    @db.rel.to
    team?: IaTeam

    @db.rel.from
    @db.rel.filterable
    issues?: IaIssue[]
}

@db.table 'ia_issues'
export interface IaIssue {
    @meta.id
    id: number

    @db.rel.FK
    ticketKey: IaTicket.key

    region: string

    status: string

    @db.column.searchable
    title: string

    secret?: string

    @db.rel.to
    @db.rel.filterable
    ticket?: IaTicket
}

@db.view 'ia_issue_board'
@db.view.for IaIssue
@db.view.joins IaTicket, `IaTicket.key = IaIssue.ticketKey`
export interface IaIssueBoard {
    id: IaIssue.id
    title: IaIssue.title
    status: IaIssue.status
    region: IaIssue.region
    teamId: IaTicket.teamId
}
