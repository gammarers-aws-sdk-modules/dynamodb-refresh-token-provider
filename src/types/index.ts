/** Unix timestamp in whole seconds. */
export type EpochSec = number;

/**
 * Configuration for the DynamoDB refresh token provider constructor.
 *
 * Token lifetime (`ttlDays`) drives both logical expiration (`expiresAt`) and the
 * DynamoDB TTL attribute (`ttl`) written on Put / Transact. Session revocation options
 * (`sessionIdIndexName`, `revokeSessionOnReuse`) require a GSI whose partition key is
 * `sessionId`.
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

  /**
   * DynamoDB GSI name whose partition key attribute is `sessionId` (String).
   * Required for {@link RefreshTokenStore.revokeSession} and for `revokeSessionOnReuse`.
   * `KEYS_ONLY` projection is sufficient.
   * @defaultValue `'sessionId-index'`
   */
  sessionIdIndexName?: string;

  /**
   * When true, {@link RefreshTokenStore.rotate} calls {@link RefreshTokenStore.revokeSession}
   * for the token’s `sessionId` and `subjectId` before throwing {@link RefreshTokenReusedError}.
   * Aligns with OAuth 2.0 BCP refresh-token family revocation on reuse detection.
   * @defaultValue false
   */
  revokeSessionOnReuse?: boolean;
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

/** Parameters for {@link RefreshTokenStore.revokeSession}. */
export type RevokeSessionParams = {
  /** Session whose refresh token rows should all be revoked. */
  sessionId: string;
  /**
   * When set, only rows matching this subject are revoked.
   * Applied as an `UpdateItem` condition on the base table (not a GSI filter), so a
   * `KEYS_ONLY` session GSI is sufficient.
   */
  subjectId?: string;
  /** Clock override for tests; defaults to `new Date()`. */
  now?: Date;
};

/** Result of {@link RefreshTokenStore.revokeSession}. */
export type RevokeSessionResult = {
  /** Number of token rows successfully updated with `revokedAt` in this call. */
  revokedCount: number;
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
  /** Subject (user) identifier; also used when cascading session revoke on reuse. */
  subjectId: string;
  /**
   * Session identifier. Partition key of the session GSI used by
   * {@link RefreshTokenStore.revokeSession}.
   */
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
 * Persistence abstraction for opaque refresh tokens: issue, rotate, revoke, and session revoke.
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
   * When reuse is detected and {@link StoreOptions.revokeSessionOnReuse} is enabled, the
   * implementation may revoke the whole session before throwing.
   *
   * @param params - Current token and optional clock.
   * @returns Subject, session, new token, and new expiration.
   * @throws {@link RefreshTokenInvalidError} When the token is invalid or no row exists.
   * @throws {@link RefreshTokenExpiredError} When `expiresAt` is not after `now`.
   * @throws {@link RefreshTokenRevokedError} When the row has `revokedAt` set.
   * @throws {@link RefreshTokenReusedError} When the token was already rotated or the transaction
   *   failed conditionally. May include `subjectId` / `sessionId` from the store row.
   */
  rotate(params: RotateParams): Promise<RotateResult>;

  /**
   * Sets `revokedAt` on the token row. Idempotent if the row does not exist.
   *
   * Does not change DynamoDB TTL (`ttl`); cleanup still follows the value from issue/rotate.
   *
   * @param params - Token to revoke and optional clock.
   * @returns `true` after a successful update or no-op when the item is absent.
   * @throws {@link RefreshTokenInvalidError} When the token string format is invalid.
   */
  revoke(params: RevokeParams): Promise<true>;

  /**
   * Sets `revokedAt` on every refresh token row for the given session (OAuth 2.0 BCP family revocation).
   *
   * Requires a DynamoDB GSI whose partition key is `sessionId` (see {@link StoreOptions.sessionIdIndexName}).
   * Optional `subjectId` is enforced on each base-table update condition.
   *
   * @param params - Session id, optional subject filter, and optional clock.
   * @returns Count of rows updated with `revokedAt`.
   */
  revokeSession(params: RevokeSessionParams): Promise<RevokeSessionResult>;
}
