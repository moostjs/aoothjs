@db.table 'test_users'
export interface TestUser {
    @meta.id
    id: string

    username: string

    @arbac.role
    roles: string[]

    @arbac.role
    extraRoles: string[]

    @arbac.attribute
    tenantId: string

    @arbac.attribute
    department: string

    secret: string
}

@db.table 'test_users_override'
export interface TestUserOverride {
    @meta.id
    id: string

    @arbac.userId
    externalId: string

    @arbac.role
    role: string

    @arbac.attribute
    tenantId: string
}
