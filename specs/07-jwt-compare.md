# Feature Spec: JWT Compare

## Goal
Compare two JWTs and highlight meaningful Header and Payload differences.

## User Story
As a developer, I want to compare a working and failing token so that I can quickly find changed claims or headers.

## Functional Requirements
- Accept Token A and Token B.
- Decode each locally.
- Compare Header objects.
- Compare Payload objects.
- Show added, removed, changed, and unchanged fields.
- Show raw values side-by-side.
- Provide friendly timestamp rendering without hiding raw values.
- Allow filtering to changed fields only.

## Acceptance Criteria
- Nested objects and arrays are compared deterministically.
- The tool does not treat signature differences as proof that claim content differs.
- Malformed input identifies which token failed to decode.
