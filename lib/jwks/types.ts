import type { JWK } from "jose";

export type JwksParseCode =
  | "OK"
  | "INVALID_JSON"
  | "INVALID_SHAPE"
  | "NO_KEYS";

export type JwksKeyEntry = {
  index: number;
  jwk: JWK;
  kid: string | null;
  kty: string;
  use: string | null;
  alg: string | null;
};

export type ParsedJwks = {
  code: "OK";
  keys: JwksKeyEntry[];
};

export type JwksParseResult =
  | ParsedJwks
  | { code: Exclude<JwksParseCode, "OK">; message: string };

export type KidMatchCode =
  | "NO_TOKEN_KID"
  | "NO_JWKS_KID"
  | "SINGLE_MATCH"
  | "MULTIPLE_MATCHES"
  | "NO_MATCH";

export type KidMatchResult = {
  code: KidMatchCode;
  message: string;
  matchedIndices: number[];
};

export type JwkCompatibility = {
  compatible: boolean;
  reasons: string[];
};
