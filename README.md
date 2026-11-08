# jwt-decode-core

JWT decoding WITHOUT verification: header/payload parse, signature
presence, caller-clock expiry. Zero runtime dependencies, Node >= 22.

> Never use this to authorize anything. Decoding is not verification.

Part of the LOFRANO TECNOLOGIA open-source lab. MIT.

```js
import { decode } from './src/jwt.mjs';
decode('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2ln');
// { header: { alg: 'HS256' }, payload: { sub: '1234' }, signaturePresent: true }
```

```sh
npm test          # 3 tests, node:test, no dependencies
npm run demo
```

At most 32768 chars; expiry helpers take your clock. MIT — see `LICENSE`.
[Versão em português](README.pt-BR.md).
