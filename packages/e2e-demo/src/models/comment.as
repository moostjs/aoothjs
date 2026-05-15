import { Tenant } from './tenant'
import { Task } from './task'

@db.table 'comments'
@db.http.path '/comments'
export interface Comment {
    @meta.id
    @db.default.uuid
    id: string

    @meta.required
    @db.rel.FK
    tenantId: Tenant.id

    @meta.required
    @db.rel.FK
    @db.index.plain 'comments_task_idx'
    taskId: Task.id

    @meta.required
    @expect.maxLength 128
    authorUsername: string

    @meta.required
    @expect.maxLength 4000
    body: string

    @db.default.now
    createdAt: number.timestamp

    @db.rel.to
    task?: Task
}
