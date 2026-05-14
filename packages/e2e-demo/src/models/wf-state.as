import { AsWfStateRecord } from '@atscript/moost-wf/store'

@db.table 'wf_states'
export interface DemoWfState extends AsWfStateRecord {
    @meta.id
    @db.default.uuid
    id: string
}
