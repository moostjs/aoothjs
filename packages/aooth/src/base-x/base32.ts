/**
 * Partially copied from "thirty-two" library, all credits to Chris Umbel.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
const charTable = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function quintetCount(buff: Buffer) {
    const quintets = Math.floor(buff.length / 5)
    return buff.length % 5 === 0 ? quintets : quintets + 1
}

export const encode = function (plain: Buffer | string) {
    if (!Buffer.isBuffer(plain) && typeof plain !== 'string') {
        throw new TypeError('base32.encode only takes Buffer or string as parameter')
    }
    if (!Buffer.isBuffer(plain)) {
        plain = Buffer.from(plain)
    }
    let i = 0
    let j = 0
    let shiftIndex = 0
    let digit = 0
    const encoded = Buffer.alloc(quintetCount(plain) * 8)
    while (i < plain.length) {
        const current = plain[i]
        if (shiftIndex > 3) {
            digit = current & (0xff >> shiftIndex)
            shiftIndex = (shiftIndex + 5) % 8
            digit = (digit << shiftIndex) | ((i + 1 < plain.length) ?
                plain[i + 1] : 0) >> (8 - shiftIndex)
            i++
        }
        else {
            digit = (current >> (8 - (shiftIndex + 5))) & 0x1f
            shiftIndex = (shiftIndex + 5) % 8
            if (shiftIndex === 0)
                i++
        }
        encoded[j] = charTable.charCodeAt(digit)
        j++
    }
    for (i = j; i < encoded.length; i++) {
        encoded[i] = 0x3d
    }
    return encoded
}
