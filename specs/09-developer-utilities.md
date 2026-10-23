# Feature Spec: Developer Utilities

## Goal
Provide small supporting utilities commonly useful while inspecting JWT/JWK material.

## Utilities
### Base64URL
- Encode text/bytes to Base64URL.
- Decode Base64URL.
- Report malformed input clearly.

### Unix Timestamp
- Convert Unix timestamps to readable UTC and browser-local time.
- Preserve and display the raw timestamp.

### JSON Formatter
- Pretty-print/minify JSON.
- Identify invalid JSON with an actionable error.

### PEM/JWK Inspector
- Parse supported public-key representations using established libraries.
- Display safe public metadata only.
- Avoid displaying or persisting private-key material unnecessarily.

## Acceptance Criteria
- Utilities work independently from the JWT Decoder.
- Inputs remain local wherever possible.
