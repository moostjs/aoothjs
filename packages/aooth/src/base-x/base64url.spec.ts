import * as base64url from './base64url'

describe('base32', function () {
    it('should encode', function () {
        const original = 'ladies and gentlemen, we are floating in space'
        const encoded = 'bGFkaWVzIGFuZCBnZW50bGVtZW4sIHdlIGFyZSBmbG9hdGluZyBpbiBzcGFjZQ'
        expect(base64url.encode(original)).toBe(encoded)
        expect(base64url.decode(encoded)).toBe(original)
    })
})
