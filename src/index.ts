/**
 * Public API: refresh token store types, DynamoDB-backed implementation, structured errors, and crypto helpers.
 *
 * Enable DynamoDB TTL on attribute `ttl`, and a `sessionId` GSI for session revocation, when using
 * {@link DynamodbRefreshTokenProvider}.
 */
export type {
  RefreshTokenStore,
  IssueParams,
  IssueResult,
  RotateParams,
  RotateResult,
  RevokeParams,
  RevokeSessionParams,
  RevokeSessionResult,
  StoreOptions,
  TokenRecord,
  EpochSec,
} from './types/index';

/**
 * DynamoDB-backed {@link RefreshTokenStore} with rotation reuse detection and optional
 * session-wide revocation (`revokeSession` / `revokeSessionOnReuse`).
 */
export { DynamodbRefreshTokenProvider } from './stores/dynamodb';

/**
 * Structured errors for `instanceof` handling in auth flows.
 * {@link RefreshTokenReusedError} may carry `subjectId` / `sessionId` for session revoke.
 */
export {
  RefreshTokenError,
  RefreshTokenExpiredError,
  RefreshTokenInvalidError,
  RefreshTokenReusedError,
  RefreshTokenRevokedError,
  RefreshTokenRotateFailedError,
} from './stores/refresh-token-errors';

/** SHA-256 hex hashing and cryptographically secure token generation. */
export { sha256hex, randomtoken } from './utils/hash';
