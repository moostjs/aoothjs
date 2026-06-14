import { Tenant } from './tenant'
import { Project } from './project'
import { Comment } from './comment'

@db.table 'tasks'
@db.http.path '/tasks'
export interface Task {
    @meta.id
    @db.default.uuid
    id: string

    @meta.required
    @db.rel.FK
    @db.index.plain 'tasks_tenant_idx'
    tenantId: Tenant.id

    @meta.required
    @db.rel.FK
    @db.index.plain 'tasks_project_idx'
    projectId: Project.id

    @meta.required
    @expect.maxLength 200
    title: string

    @meta.required
    @expect.maxLength 128
    creatorUsername: string

    @ui.form.options 'open', 'open'
    @ui.form.options 'in_progress', 'in_progress'
    @ui.form.options 'done', 'done'
    status: 'open' | 'in_progress' | 'done'

    @expect.maxLength 4000
    description?: string

    @db.index.plain 'tasks_assignee_idx'
    @expect.maxLength 128
    assigneeUsername?: string

    @ui.form.options 'low', 'low'
    @ui.form.options 'medium', 'medium'
    @ui.form.options 'high', 'high'
    priority?: 'low' | 'medium' | 'high'

    dueDate?: number.timestamp

    @expect.maxLength 4000
    internalNotes?: string

    @db.default.now
    createdAt: number.timestamp

    @db.default.now
    updatedAt: number.timestamp

    @db.rel.from
    comments?: Comment[]
}

export interface NewTaskForm {
    @meta.required
    projectId: string

    @meta.required
    @expect.maxLength 200
    title: string

    @expect.maxLength 4000
    description?: string

    @expect.maxLength 128
    assigneeUsername?: string

    @ui.form.options 'low', 'low'
    @ui.form.options 'medium', 'medium'
    @ui.form.options 'high', 'high'
    priority?: 'low' | 'medium' | 'high'

    dueDate?: number.timestamp
}

export interface AssignTaskForm {
    @meta.required
    @expect.maxLength 128
    assigneeUsername: string
}
