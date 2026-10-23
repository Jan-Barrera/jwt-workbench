# Feature Spec: JWT Decoder

## Goal
Allow a developer to paste a JWT and immediately inspect its constituent parts without sending the token to the application server.

## User Story
As a developer, I want to decode a JWT so that I can inspect its header and claims while debugging authentication and authorization issues.

## Functional Requirements
- Accept a raw compact JWT (`header.payload.signature`).
- Also recognize a token prefixed with `Bearer ` and extract the JWT.
- Display Header, Payload, and Signature as separate sections.
- Pretty-print Header and Payload JSON with syntax highlighting.
- Visually distinguish the three encoded JWT segments.
- Provide copy actions for Header, Payload, Signature, and full JWT.
- Detect malformed JWT structure and invalid Base64URL/JSON content.
- Do not claim that a decoded token is valid unless it has separately been verified.

## Privacy & Security
- Decode locally in the browser.
- Do not send pasted JWTs to the server.
- Do not persist JWTs to cookies, analytics, logs, databases, or browser storage by default.
- Clearly show a local-processing privacy indicator.

## Acceptance Criteria
- A valid JWT renders decoded Header and Payload JSON.
- A malformed token produces a clear error without crashing the page.
- The UI distinguishes `decoded` from `verified`.
- Reloading the page does not restore a pasted JWT by default.
