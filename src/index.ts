/**
 * Public API: refresh token store types, DynamoDB-backed implementation, structured errors, and crypto helpers.
 *
 * Enable DynamoDB TTL on attribute `ttl`, and GSIs on `sessionId` and `subjectId` for bulk
 * revocation, when using {@link DynamodbRefreshTokenProvider}.
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
  RevokeSubjectParams,
  RevokeSubjectResult,
  DocumentClientTranslateConfig,
  StoreOptions,
  TokenRecord,
  EpochSec,
} from './core/types';

/**
 * DynamoDB-backed {@link RefreshTokenStore} with rotation reuse detection and optional
 * session-wide revocation (`revokeSession` / `revokeSessionOnReuse`) and subject-wide
 * revocation (`revokeSubject`).
 */
export { DynamodbRefreshTokenProvider } from './dynamodb-refresh-token-provider';

/**
 * Structured errors for `instanceof` handling in auth flows.
 * Check a concrete subclass before {@link DynamodbRefreshTokenProviderError}.
 * {@link DynamodbRefreshTokenProviderReusedError} may carry `subjectId` / `sessionId` for session revoke.
 * {@link DynamodbRefreshTokenProviderRotateError} marks a non-reuse rotate failure that may be retried.
 */
export type {
  DynamodbRefreshTokenProviderReusedErrorContext,
  DynamodbRefreshTokenProviderRotateErrorOptions,
} from './core/errors';
export {
  DynamodbRefreshTokenProviderError,
  DynamodbRefreshTokenProviderValidateError,
  DynamodbRefreshTokenProviderExpiredError,
  DynamodbRefreshTokenProviderInvalidError,
  DynamodbRefreshTokenProviderReusedError,
  DynamodbRefreshTokenProviderRevokedError,
  DynamodbRefreshTokenProviderRotateError,
} from './core/errors';

/** SHA-256 hex hashing and cryptographically secure token generation. */
export { sha256Hex, randomToken } from './core/hash';
