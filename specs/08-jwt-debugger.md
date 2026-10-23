# Feature Spec: JWT Debugger

## Goal
Combine decoding, claim inspection, configured validation, key matching, and signature-verification evidence into a single troubleshooting view.

## Functional Requirements
- Show token structure status.
- Summarize recognized claims and temporal status.
- Show configured issuer/audience checks.
- Show JWT algorithm and `kid` when present.
- Incorporate JWKS/key-matching results when supplied.
- Incorporate signature-verification results when actually performed.
- Explain individual failures using actionable, factual messages.
- Separate validation failures from advisory security observations.

## Diagnostic Principles
- Never infer that a token is trusted merely because it decodes successfully.
- Never report signature validity without cryptographic verification.
- Clearly state which checks were not performed.
- Avoid treating optional claims as universally required.

## Acceptance Criteria
- The report provides evidence for every pass/fail status.
- Unperformed checks display an explicit neutral state.
- A user can understand whether failure relates to structure, time, configured claims, key selection, or signature.
