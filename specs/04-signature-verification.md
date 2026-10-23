# Feature Spec: Signature Verification

## Goal
Allow users to cryptographically verify a JWT using explicitly supplied trusted key material.

## Functional Requirements
- Read the JWT-declared signing algorithm.
- Support an intentionally defined set of algorithms using a maintained JWT/JWS library rather than custom cryptography.
- Accept appropriate verification material such as a shared secret, public key, or selected JWK.
- Clearly distinguish verification success, failure, unsupported algorithm, malformed key, and missing key.
- Never silently choose a weaker/different algorithm than requested by the JWT and verifier policy.

## Security Requirements
- Verification keys and secrets remain client-side whenever possible.
- Never log, persist, or transmit secrets by default.
- Do not expose private keys unless a feature explicitly requires them.
- Use established platform/library cryptographic implementations.

## Acceptance Criteria
- Modified header/payload/signature causes verification failure.
- Unsupported algorithms fail safely.
- Verification status cannot be confused with simple decoding status.
