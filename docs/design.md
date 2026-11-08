# Design — jwt-decode-core

Split on exactly two dots, decode segments as base64url, require JSON
objects. The signature segment is validated for character set and
presence only — cryptographic verification is a deliberate non-goal,
stated in the README so no caller mistakes decoding for trust.

Oracle: a fixed HS256 token with known header/payload, the `none`
shape, structural rejections, and expiry checks against fixed clocks.
The library holds no secrets and reads no clock.
