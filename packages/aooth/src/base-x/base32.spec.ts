import * as base32 from './base32'

describe('base32', function () {
    it('should encode', function () {
        expect(base32.encode('a').toString()).toBe('ME======')
        expect(base32.encode('be').toString()).toBe('MJSQ====')
        expect(base32.encode('bee').toString()).toBe('MJSWK===')
        expect(base32.encode('beer').toString()).toBe('MJSWK4Q=')
        expect(base32.encode('beers').toString()).toBe('MJSWK4TT')
        expect(base32.encode('beers 1').toString()).toBe('MJSWK4TTEAYQ====')
        expect(base32.encode('shockingly dismissed').toString()).toBe('ONUG6Y3LNFXGO3DZEBSGS43NNFZXGZLE')
    })

    it('should be binary safe', function () {
        expect(base32.encode(Buffer.from('f61e1f998d69151de8334dbe753ab17ae831c13849a6aecd95d0a4e5dc25', 'hex')).toString()).toBe('6YPB7GMNNEKR32BTJW7HKOVRPLUDDQJYJGTK5TMV2CSOLXBF')
    })
})
