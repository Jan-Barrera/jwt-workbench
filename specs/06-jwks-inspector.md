# Feature Spec: JWKS Inspector

## Goal
Inspect a JSON Web Key Set and use an explicitly selected/matched key to troubleshoot JWT signature verification.

## Functional Requirements
- Accept a JWKS URL or pasted JWKS JSON.
- Display keys with relevant fields such as `kid`, `kty`, `use`, and `alg` when present.
- Read `kid` from a JWT header and highlight matching keys.
- Allow a selected compatible JWK to be used for signature verification.
- Handle unreachable endpoints, invalid JSON, invalid JWKS shape, no matching `kid`, multiple candidates, and incompatible keys.

## Network Boundary
- Clearly indicate when the application will make a network request.
- A JWT should not be sent to the JWKS endpoint.
- Apply safe URL-fetching controls if JWKS retrieval is performed server-side.

## Acceptance Criteria
- Pasted JWKS works without a remote request.
- Matching is explicit and visible to the user.
- Lack of a matching key is not reported as an invalid JWT signature until verification is actually attempted with appropriate material.
