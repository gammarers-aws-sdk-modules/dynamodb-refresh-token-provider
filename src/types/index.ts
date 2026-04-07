/** Unix timestamp in whole seconds. */
export type EpochSec = number;

export type StoreOptions = {
  /**
   * Refresh token time-to-live in days.
   * @defaultValue 60
   */
  ttlDays?: number;

  /**
   * Partition key prefix for DynamoDB items.
   * @defaultValue `'rt#'`
   */
  pkPrefix?: string;

  /**
   * Whether to use strongly consistent reads on GetItem.
   * @defaultValue true
   */
  consistentRead?: boolean;

  /**
   * Custom DynamoDB API endpoint (e.g. for LocalStack or DynamoDB Local).
   */
  endpoint?: string;
};

export type IssueParams = {
  /** Subject (user) identifier to associate with the token. */
  subjectId: string;
  /** Session identifier to associate with the token. */
  sessionId: string;
  /** Clock override for tests; defaults to `new Date()`. */
  now?: Date;
};

export type IssueResult = {
  /** Opaque refresh token string (plaintext; store only a hash at rest). */
  refreshToken: string;
  /** Expiration time as Unix seconds. */
  refreshTokenExpiresAt: EpochSec;
};

export type RotateParams = {
  /** Current refresh token from the client. */
  refreshToken: string;
  /** Clock override for tests; defaults to `new Date()`. */
  now?: Date;
};

export type RotateResult = {
  subjectId: string;
  sessionId: string;
  /** New opaque refresh token after rotation. */
  refreshToken: string;
  /** Expiration time of the new token as Unix seconds. */
  refreshTokenExpiresAt: EpochSec;
};

export type RevokeParams = {
  /** Refresh token to revoke. */
  refreshToken: string;
  /** Clock override for tests; defaults to `new Date()`. */
  now?: Date;
};

/** DynamoDB item shape for a stored refresh token (hash-keyed). */
export type TokenRecord = {
  pk: string;
  subjectId: string;
  sessionId: string;

  createdAt: EpochSec;
  expiresAt: EpochSec;

  rotatedAt?: EpochSec | null;
  replacedByPk?: string | null;
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
   */
  issue(params: IssueParams): Promise<IssueResult>;

  /**
   * Validates the current token, marks it rotated, inserts the successor row, and returns the new token.
   *
   * @param params - Current token and optional clock.
   */
  rotate(params: RotateParams): Promise<RotateResult>;

  /**
   * Sets `revokedAt` on the token row. Idempotent if the row does not exist.
   *
   * @param params - Token to revoke and optional clock.
   */
  revoke(params: RevokeParams): Promise<true>;
}
