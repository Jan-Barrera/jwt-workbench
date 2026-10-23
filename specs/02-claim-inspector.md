# Feature Spec: Claim Inspector

## Goal
Convert JWT claims into human-friendly information while preserving the original claim values.

## User Story
As a developer, I want common JWT claims explained and timestamps rendered as readable dates so that I can understand a token quickly.

## Functional Requirements
- Recognize common registered claims: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, and `jti`.
- Show the original value for every claim.
- Render numeric date claims (`exp`, `nbf`, `iat`) as human-readable local and UTC timestamps.
- Show whether the current time is before `nbf` or after `exp`.
- Display unknown/custom claims without modification.
- Provide concise descriptions for recognized claims.
- Handle `aud` as either a string or array.

## UX
A claim row should contain: claim name, friendly name, raw value, interpreted value when applicable, and status when meaningful.

## Acceptance Criteria
- Timestamp conversion never replaces the original numeric value.
- Expired tokens are clearly identified as expired.
- Future `nbf` values are clearly identified as not yet valid.
- Custom claims remain visible and unchanged.
