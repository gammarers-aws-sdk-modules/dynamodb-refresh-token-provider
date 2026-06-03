/** Unix timestamp in whole seconds. */
export type EpochSec = number;

/**
 * Configuration for the DynamoDB refresh token provider constructor.
 *
 * Token lifetime (`ttlDays`) drives both logical expiration (`expiresAt`) and the
 * DynamoDB TTL attribute (`ttl`) written on Put / Transact.
 */
export type StoreOptions = {
  /**
   * Refresh token lifetime in days (added to `now` when computing `expiresAt` / `ttl`).
   * @defaultValue 60
   */
  ttlDays?: number;

  /**
   * Partition key prefix for DynamoDB items; full `pk` is `prefix` + SHA-256 hex of the token.
   * @defaultValue `'rt#'`
   */
  pkPrefix?: string;

  /**
   * Whether to use strongly consistent reads on `GetItem`.
   * @defaultValue true
   */
  consistentRead?: boolean;

  /**
   * Custom DynamoDB API endpoint (e.g. LocalStack or DynamoDB Local).
   */
  endpoint?: string;
};

/** Parameters for {@link RefreshTokenStore.issue}. */
export type IssueParams = {
  /** Subject (user) identifier to associate with the token. */
  subjectId: string;
  /** Session identifier to associate with the token. */
  sessionId: string;
  /** Clock override for tests; defaults to `new Date()`. */
  now?: Date;
};

/** Result of {@link RefreshTokenStore.issue}. */
export type IssueResult = {
  /** Opaque refresh token string (plaintext; only a hash is stored at rest). */
  refreshToken: string;
  /** Logical expiration time as Unix seconds (same value written to `expiresAt` / `ttl`). */
  refreshTokenExpiresAt: EpochSec;
};

/** Parameters for {@link RefreshTokenStore.rotate}. */
export type RotateParams = {
  /** Current refresh token from the client. */
  refreshToken: string;
  /** Clock override for tests; defaults to `new Date()`. */
  now?: Date;
};

/** Result of {@link RefreshTokenStore.rotate}. */
export type RotateResult = {
  /** Subject identifier from the rotated token row. */
  subjectId: string;
  /** Session identifier from the rotated token row. */
  sessionId: string;
  /** New opaque refresh token after rotation. */
  refreshToken: string;
  /** Logical expiration of the new token as Unix seconds. */
  refreshTokenExpiresAt: EpochSec;
};

/** Parameters for {@link RefreshTokenStore.revoke}. */
export type RevokeParams = {
  /** Refresh token to revoke. */
  refreshToken: string;
  /** Clock override for tests; defaults to `new Date()`. */
  now?: Date;
};

/**
 * DynamoDB item shape for a stored refresh token (hash-keyed by `pk`).
 *
 * `expiresAt` is used for application-level validation; `ttl` is the DynamoDB TTL
 * attribute for asynchronous item deletion (enable TTL on the table for attribute `ttl`).
 */
export type TokenRecord = {
  /** Partition key: prefix + SHA-256 hex of the plaintext token. */
  pk: string;
  /** Subject (user) identifier. */
  subjectId: string;
  /** Session identifier. */
  sessionId: string;
  /** Row creation time as Unix seconds. */
  createdAt: EpochSec;
  /** Logical expiration time as Unix seconds. */
  expiresAt: EpochSec;
  /**
   * DynamoDB TTL attribute (Unix seconds). Set on write; table TTL must target this attribute name.
   */
  ttl: EpochSec;
  /** Time the token was rotated, if applicable. */
  rotatedAt?: EpochSec | null;
  /** Partition key of the successor token after rotation. */
  replacedByPk?: string | null;
  /** Time the token was revoked, if applicable. */
  revokedAt?: EpochSec | null;
};

/**
 * Persistence abstraction for opaque refresh tokens: issue, rotate, and revoke.
 */
export interface RefreshTokenStore {
  /**
   * Creates a new refresh token row and returns the plaintext token.
   *
   * @param params - Subject, session, and optional clock.
   * @returns Plaintext token and expiration as Unix seconds.
   */
  issue(params: IssueParams): Promise<IssueResult>;

  /**
   * Validates the current token, marks it rotated, inserts the successor row, and returns the new token.
   *
   * @param params - Current token and optional clock.
   * @returns Subject, session, new token, and new expiration.
   * @throws {@link RefreshTokenInvalidError} When the token is invalid or no row exists.
   * @throws {@link RefreshTokenExpiredError} When `expiresAt` is not after `now`.
   * @throws {@link RefreshTokenRevokedError} When the row has `revokedAt` set.
   * @throws {@link RefreshTokenReusedError} When the token was already rotated or the transaction failed conditionally.
   */
  rotate(params: RotateParams): Promise<RotateResult>;

  /**
   * Sets `revokedAt` on the token row. Idempotent if the row does not exist.
   *
   * @param params - Token to revoke and optional clock.
   * @returns `true` after a successful update or no-op when the item is absent.
   * @throws {@link RefreshTokenInvalidError} When the token string format is invalid.
   */
  revoke(params: RevokeParams): Promise<true>;
}
