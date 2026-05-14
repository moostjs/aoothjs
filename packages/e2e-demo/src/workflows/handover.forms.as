@meta.label 'Handover target'
export interface HandoverTargetForm {
    @meta.required
    @expect.maxLength 200
    projectId: string

    @meta.required
    @expect.maxLength 128
    targetOwner: string
}

@meta.label 'Confirm handover'
export interface HandoverConfirmForm {
    @meta.required
    confirm: boolean
}
