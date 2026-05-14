import { AoothArbacUserCredentials } from '@aoothjs/arbac-moost/atscript/models'

@db.table 'users'
@db.http.path '/users'
export interface DemoUser extends AoothArbacUserCredentials {
    @meta.id
    @db.default.uuid
    id: string

    @arbac.attribute
    @meta.required
    @expect.maxLength 64
    tenantId: string

    @arbac.attribute
    @expect.maxLength 64
    departmentId?: string

    @expect.maxLength 128
    email?: string

    @expect.maxLength 1000
    secretNotes?: string

    @db.default.now
    createdAt: number.timestamp
}

export interface AssignRolesForm {
    @meta.required
    roles: string[]
}

export interface LockForm {
    @meta.required
    @expect.maxLength 200
    reason: string

    durationMs?: number
}
