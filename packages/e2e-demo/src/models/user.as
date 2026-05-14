import { AoothArbacUserCredentials } from '@aoothjs/arbac-moost/atscript/models'
import { Tenant } from './tenant'
import { Department } from './department'

@db.table 'users'
@db.http.path '/users'
export interface DemoUser extends AoothArbacUserCredentials {
    @meta.id
    @db.default.uuid
    id: string

    @arbac.attribute
    @meta.required
    @db.rel.FK
    tenantId: Tenant.id

    @arbac.attribute
    @db.rel.FK
    departmentId?: Department.id

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
