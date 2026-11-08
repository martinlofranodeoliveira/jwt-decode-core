# Contract — jwt-decode-core

Pure ESM in `src/jwt.mjs` (base64 via `node:buffer`), zero runtime
dependencies, Node >= 22. Decoding only — this library CANNOT verify
signatures and its output must never authorize anything.

| Export | Result |
| --- | --- |
| `MAX_TOKEN` (32768) | Hard bound. |
| `decode(token)` | Frozen `{ header, payload, signaturePresent }`. Empty signature allowed (`alg:none` shape); non-empty must be base64url chars. |
| `check(token)` | `{ ok:true, ... }` or `{ ok:false, code }`. |
| `hasExpiry(payload)` / `isExpiredAt(payload, nowSec)` | Expiry inspection with a caller-supplied clock (the library never reads time). |

Errors: `NOT_STRING` · `EMPTY` · `TOO_BIG` · `BAD_PARTS` ·
`BAD_SEGMENT` · `BAD_LENGTH` · `BAD_BASE64` · `BAD_JSON` ·
`BAD_SIGNATURE_CHARS` · `NO_EXP` · `BAD_CLOCK`.
