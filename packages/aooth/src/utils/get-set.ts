import { TChangeOperation } from '../types'

export function getValue<T, O>(target: T, path: string): O {
    const parts = path.split('.')
    let current: T = target

    for (const part of parts) {
        if (current[part as keyof T] === undefined) {
            return undefined as O
        }
        current = current[part as keyof T] as T
    }

    return current as unknown as O
}

export function setValue<T>(target: T, path: string, value: unknown, op: TChangeOperation = 'set') {
    const parts = path.split('.')
    let current: T = target

    for (let i = 0; i < parts.length; i++) {
        const part = parts[i] as keyof typeof current
        const nextPart = parts[i + 1] as keyof typeof current

        if (!current[part]) {
            if (op === 'unset') return
            if (nextPart) {
                if (Number.isInteger(parseInt(nextPart as string))) {
                    current[part] = [] as T[keyof T]
                } else {
                    current[part] = {} as T[keyof T]
                }
            }
        }

        if (i === parts.length - 1) {
            switch (op) {
                case 'set':
                    current[part] = value as T[keyof T]
                    break
                case 'unset':
                    delete current[part]
                    break
                case 'inc':
                    current[part] = ((current[part] as number || 0) + (value as number)) as T[keyof T]
                    break
            }
        } else {
            current = current[part] as T
        }
    }
}

export function unsetAll<T>(obj: T) {
    for (const prop in obj) {
        // eslint-disable-next-line @typescript-eslint/ban-types
        if ((obj as object).hasOwnProperty(prop)) {
            delete obj[prop]
        }
    }
}

export function deepClone<T>(obj: T): T {
    if (obj === null || typeof obj !== 'object') {
        return obj
    }

    const clone: T = (Array.isArray(obj) ? [] : {}) as T

    for (const i in obj) {
        if (obj[i] && typeof obj[i] == 'object') {
            clone[i] = deepClone(obj[i])
        } else {
            clone[i] = obj[i]
        }
    }

    return clone
}
