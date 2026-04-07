/**
 * Public API: refresh token store types, DynamoDB-backed implementation, errors, and crypto helpers.
 */
export type {
  RefreshTokenStore,
  IssueParams,
  IssueResult,
  RotateParams,
  RotateResult,
  RevokeParams,
  StoreOptions,
  TokenRecord,
  EpochSec,
} from './types/index';

export { DynamoRefreshTokenStore } from './stores/dynamodb';
export {
  RefreshTokenError,
  RefreshTokenExpiredError,
  RefreshTokenInvalidError,
  RefreshTokenReusedError,
  RefreshTokenRevokedError,
  RefreshTokenRotateFailedError,
} from './stores/refresh-token-errors';
export { sha256hex, randomtoken } from './utils/hash';
