# Cross-Cutting Spec: Privacy & Security

## Goal
Make privacy and trust a first-class characteristic of JWT Workbench.

## Principles
1. Local-first processing for JWT decoding, comparison, formatting, claim inspection, and suitable cryptographic operations.
2. No token persistence by default.
3. No token/secret/private-key content in analytics, telemetry, application logs, error reporting, URLs, or referrers.
4. Network operations must be visible to the user.
5. Decoding, validation, and cryptographic verification must be presented as distinct states.
6. Established cryptographic libraries/platform APIs must be used instead of custom cryptographic primitives.

## UI Requirements
- Display a visible privacy indicator for local-only operations.
- Warn before an operation sends data over the network.
- Provide a clear `Clear` action that removes sensitive values from the current UI state.
- Never place the JWT in a query string or route URL.

## Acceptance Criteria
- Inspecting a JWT locally produces no application-server request containing the JWT.
- Refreshing the page does not restore sensitive values unless the user explicitly enabled a future opt-in persistence feature.
- Telemetry/error reporting is scrubbed of JWTs and key material.
