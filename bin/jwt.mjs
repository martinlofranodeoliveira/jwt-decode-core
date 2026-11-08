#!/usr/bin/env node
// Demo: decode a fixed token, assert fields. --assert exits non-zero on mismatch.
import { decode } from '../src/jwt.mjs';

const TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwiZXhwIjoxODkzNDU2MDAwfQ.c2ln';

let failed = 0;
try {
  const r = decode(TOKEN);
  const pass = r.header.alg === 'HS256' && r.payload.sub === '1234' && r.payload.exp === 1893456000 && r.signaturePresent;
  console.log(`${pass ? 'PASS' : 'FAIL'} HS256 token -> alg=${r.header.alg} sub=${r.payload.sub}`);
  if (!pass) failed++;
} catch (e) {
  failed++;
  console.log(`FAIL threw ${e.code}`);
}
if (process.argv.includes('--assert') && failed > 0) process.exit(1);
if (failed > 0) process.exitCode = 1;
console.log(failed === 0 ? 'demo: all cases as expected' : `demo: ${failed} mismatch(es)`);
