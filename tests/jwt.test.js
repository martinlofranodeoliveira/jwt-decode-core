import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { decode, check, hasExpiry, isExpiredAt, JwtError } from '../src/jwt.mjs';

// Header {"alg":"HS256","typ":"JWT"}, payload {"sub":"1234","exp":1893456000}.
const HS = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwiZXhwIjoxODkzNDU2MDAwfQ.c2ln';
const NONE_ALG = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0In0.';

describe('decode', () => {
  it('decodes header and payload, reports signature presence', () => {
    const r = decode(HS);
    assert.equal(r.header.alg, 'HS256');
    assert.equal(r.payload.sub, '1234');
    assert.equal(r.signaturePresent, true);
    const n = decode(NONE_ALG);
    assert.equal(n.header.alg, 'none');
    assert.equal(n.signaturePresent, false);
  });
  it('rejects structural problems', () => {
    assert.equal(check('a.b').code, 'BAD_PARTS');
    assert.equal(check('a.b.c.d').code, 'BAD_PARTS');
    assert.equal(check('').code, 'EMPTY');
    assert.equal(check('!!!.e30.e30').code, 'BAD_SEGMENT');
    assert.throws(() => decode(42), (e) => e.code === 'NOT_STRING');
    assert.ok(new JwtError('X') instanceof Error);
  });
});

describe('expiry helpers (caller clock)', () => {
  it('detects exp without reading the clock', () => {
    const { payload } = decode(HS);
    assert.equal(hasExpiry(payload), true);
    assert.equal(hasExpiry({}), false);
    assert.equal(isExpiredAt(payload, 1893456001), true);
    assert.equal(isExpiredAt(payload, 1893455999), false);
    assert.throws(() => isExpiredAt({}, 1), (e) => e.code === 'NO_EXP');
  });
});
