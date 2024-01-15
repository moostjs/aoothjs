export function decode(str: string): string {
    // Add padding
    str = str.padEnd(str.length + (4 - (str.length % 4)) % 4, '=')

    // Convert '-' to '+', '_' to '/' for base64 decoding
    const base64 = str.replace(/\-/g, '+').replace(/_/g, '/')

    return Buffer.from(base64, 'base64').toString()
}

export function encode(str: string): string {
    return Buffer.from(str)
        .toString('base64')
        .replace(/=/g, '')        // Remove padding (=)
        .replace(/\+/g, '-')      // Replace + with -
        .replace(/\//g, '_')      // Replace / with _
}

