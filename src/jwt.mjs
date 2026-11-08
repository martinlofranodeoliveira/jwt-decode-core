// SPDX-License-Identifier: MIT
// JWT decoding WITHOUT verification: split, base64url-decode, JSON-parse
// header and payload. Never trusts the token — signature is opaque bytes.
// No network, no I/O.

export const MAX_TOKEN = 32768;

export class JwtError extends Error {
  constructor(code, detail = '') {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'JwtError';
    this.code = code;
  }
}

function b64urlDecode(part) {
  if (!/^[A-Za-z0-9_-]*$/.test(part) || part.length === 0) throw new JwtError('BAD_SEGMENT');
  if (part.length % 4 === 1) throw new JwtError('BAD_LENGTH');
  const b64 = part.replace(/-/g, '+').replace(/_/g, '/');
  let json;
  try {
    json = Buffer.from(b64, 'base64').toString('utf8');
  } catch {
    throw new JwtError('BAD_BASE64');
  }
  try {
    const value = JSON.parse(json);
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    return value;
  } catch {
    throw new JwtError('BAD_JSON');
  }
}

/**
 * Decode an unverified JWT. Returns { header, payload, signaturePresent }.
 * Throws on structural problems; NEVER verifies — see docs/contract.md.
 */
export function decode(token) {
  if (typeof token !== 'string') throw new JwtError('NOT_STRING');
  const t = token.trim();
  if (t.length === 0) throw new JwtError('EMPTY');
  if (t.length > MAX_TOKEN) throw new JwtError('TOO_BIG');
  const parts = t.split('.');
  if (parts.length !== 3) throw new JwtError('BAD_PARTS');
  const header = b64urlDecode(parts[0]);
  const payload = b64urlDecode(parts[1]);
  const signaturePresent = parts[2].length > 0;
  if (parts[2] && !/^[A-Za-z0-9_-]+$/.test(parts[2])) throw new JwtError('BAD_SIGNATURE_CHARS');
  return Object.freeze({ header: Object.freeze(header), payload: Object.freeze(payload), signaturePresent });
}

/** Non-throwing: { ok:true, ... } or { ok:false, code }. */
export function check(token) {
  try {
    return { ok: true, ...decode(token) };
  } catch (err) {
    if (err instanceof JwtError) return { ok: false, code: err.code };
    throw err;
  }
}

/** True when payload.exp exists and is a finite number (no clock read). */
export function hasExpiry(payload) {
  return typeof payload?.exp === 'number' && Number.isFinite(payload.exp);
}

/** True when payload.exp <= nowSec (caller supplies the clock). */
export function isExpiredAt(payload, nowSec) {
  if (!hasExpiry(payload)) throw new JwtError('NO_EXP');
  if (typeof nowSec !== 'number' || !Number.isFinite(nowSec)) throw new JwtError('BAD_CLOCK');
  return payload.exp <= nowSec;
}
