# Feature Spec: JWT Generator

## Goal
Provide a developer-oriented builder for creating test JWTs and signing them with user-provided or locally generated key material.

## Functional Requirements
- Edit JWT Header as structured JSON or supported form fields.
- Build Payload using registered and custom claims.
- Configure issuer, subject, audience, issued-at, not-before, and expiration.
- Add/remove custom claims.
- Select from explicitly supported signing algorithms.
- Sign locally where practical.
- Copy the generated compact JWT.
- Decode the generated token immediately for inspection.

## Safety
- Label generated tokens as development/testing artifacts.
- Do not upload signing secrets/private keys to the backend by default.
- Do not automatically persist generated tokens.

## Acceptance Criteria
- Generated tokens can be decoded by the Decoder.
- A generated signed token can be verified using its corresponding verification material.
- Invalid JSON/claim values prevent generation and show actionable errors.
