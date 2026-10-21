import { InviteForm } from '../../atscript/models/forms'

// An app's extended admin invite form (extra field reaches the invite hooks).
@wf.context.pass 'public'
export interface ExtendedInviteForm extends InviteForm {
    displayName?: string
}
