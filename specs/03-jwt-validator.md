# Feature Spec: JWT Validator

## Goal
Validate token structure, temporal claims, configurable expectations, and optionally the cryptographic signature.

## User Story
As a developer debugging a 401/403 response, I want detailed JWT validation results so that I can identify the failing condition.

## Functional Requirements
- Validate token structure.
- Evaluate `exp` and `nbf` when present.
- Support expected issuer (`iss`).
- Support expected audience (`aud`).
- Support configurable clock tolerance.
- Integrate signature-verification results when verification material is supplied.
- Report each check independently rather than returning only `valid/invalid`.
- Distinguish errors, warnings, and informational findings.

## Example Result
- Token structure: Pass
- Expiration: Pass
- Not Before: Pass
- Issuer: Pass
- Audience: Fail, expected `orders-api`, received `payments-api`
- Signature: Not verified

## Acceptance Criteria
- Failure of one check does not hide other validation results.
- Missing signature-verification material is shown as `Not verified`, not `Valid`.
- Expected and actual values appear for issuer/audience mismatches.
