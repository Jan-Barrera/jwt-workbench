# JWT Workbench Specs

A set of implementation-oriented feature specifications for the proposed Next.js JWT Workbench.

## Feature Specs
1. [JWT Decoder](01-jwt-decoder.md)
2. [Claim Inspector](02-claim-inspector.md)
3. [JWT Validator](03-jwt-validator.md)
4. [Signature Verification](04-signature-verification.md)
5. [JWT Generator](05-jwt-generator.md)
6. [JWKS Inspector](06-jwks-inspector.md)
7. [JWT Compare](07-jwt-compare.md)
8. [JWT Debugger](08-jwt-debugger.md)
9. [Developer Utilities](09-developer-utilities.md)

## Cross-Cutting Specs
10. [Privacy & Security](10-privacy-security.md)
11. [Non-Functional Requirements](11-non-functional-requirements.md)

## Suggested Delivery Order
**MVP:** Decoder → Claim Inspector → Validator → Signature Verification

**V2:** JWKS Inspector → Compare → Generator

**V3:** Unified Debugger → Developer Utilities

Privacy/security and non-functional requirements apply across all phases.
