import { TChangeOperation, TCumulativeChanges } from './types'

export abstract class Changeable {
    constructor(protected changes: TCumulativeChanges) {}

    protected abstract getCurrentValue(path: string): unknown

    pushChange(path: string, op: TChangeOperation, value: unknown) {
        if (this.changes[path]) {
            this.changes[path].value = value
            this.changes[path].op = op
        } else {
            this.changes[path] = {
                oldValue: this.getCurrentValue(path),
                value,
                op,
            }
        }
    }
}
