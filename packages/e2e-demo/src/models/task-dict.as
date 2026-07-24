import { Task } from './task'

// Managed dict-style view over tasks (value-help posture: id + label columns).
// Deliberately bound to the WRITABLE AsArbacDbController in
// task-dict.controller.ts — regression surface for the read-side `.table`
// misuse (moost-db's `.table` getter throws for view-bound controllers).
@db.view 'taskDict'
@db.view.for Task
@db.http.path '/task-dict'
export interface TaskDict {
    @meta.id
    id: Task.id

    tenantId: Task.tenantId

    title: Task.title

    status: Task.status
}
