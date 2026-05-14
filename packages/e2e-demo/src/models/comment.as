@db.table 'comments'
@db.http.path '/comments'
export interface Comment {
    @meta.id
    @db.default.uuid
    id: string

    @meta.required
    tenantId: string

    @meta.required
    @db.index.plain 'comments_task_idx'
    taskId: string

    @meta.required
    @expect.maxLength 128
    authorUsername: string

    @meta.required
    @expect.maxLength 4000
    body: string

    @db.default.now
    createdAt: number.timestamp
}
