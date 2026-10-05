/**
 * Base class for errors thrown by this package.
 * Use `instanceof` on a concrete subclass, or on this base, to tell them apart from other failures.
 */
export abstract class DynamodbRefreshTokenProviderError extends Error {
  override readonly name: string = 'DynamodbRefreshTokenProviderError';

  /**
   * @param message - Human-readable error description.
   */
  protected constructor(message: string) {
    super(message);
    Object.setPrototypeOf(this, DynamodbRefreshTokenProviderError.prototype);
  }
}

/**
 * Thrown when constructor options are inconsistent or out of range.
 */
export class DynamodbRefreshTokenProviderValidateError extends DynamodbRefreshTokenProviderError {
  override readonly name: string = 'DynamodbRefreshTokenProviderValidateError';

  /**
   * @param message - Human-readable error description.
   */
  constructor(message: string) {
    super(message);
    Object.setPrototypeOf(this, DynamodbRefreshTokenProviderValidateError.prototype);
  }
}

/**
 * Thrown when the refresh token is missing, malformed, or not recognized.
 */
export class DynamodbRefreshTokenProviderInvalidError extends DynamodbRefreshTokenProviderError {
  override readonly name: string = 'DynamodbRefreshTokenProviderInvalidError';

  /**
   * @param message - Human-readable error description.
   */
  constructor(
    message = 'The refresh token is missing, malformed, or not recognized.',
  ) {
    super(message);
    Object.setPrototypeOf(this, DynamodbRefreshTokenProviderInvalidError.prototype);
  }
}

/**
 * Thrown when the refresh token has passed its logical expiration (`expiresAt`).
 */
export class DynamodbRefreshTokenProviderExpiredError extends DynamodbRefreshTokenProviderError {
  override readonly name: string = 'DynamodbRefreshTokenProviderExpiredError';

  /**
   * @param message - Human-readable error description.
   */
  constructor(message = 'The refresh token has expired. Please sign in again.') {
    super(message);
    Object.setPrototypeOf(this, DynamodbRefreshTokenProviderExpiredError.prototype);
  }
}

/**
 * Thrown when the refresh token has been explicitly revoked.
 */
export class DynamodbRefreshTokenProviderRevokedError extends DynamodbRefreshTokenProviderError {
  override readonly name: string = 'DynamodbRefreshTokenProviderRevokedError';

  /**
   * @param message - Human-readable error description.
   */
  constructor(message = 'The refresh token has been revoked.') {
    super(message);
    Object.setPrototypeOf(this, DynamodbRefreshTokenProviderRevokedError.prototype);
  }
}

/**
 * Optional identifiers attached when refresh token reuse is detected, so callers can
 * revoke the whole session (e.g. via {@link RefreshTokenStore.revokeSession}).
 */
export type DynamodbRefreshTokenProviderReusedErrorContext = {
  /** Subject identifier from the reused token row, when known. */
  subjectId?: string;
  /** Session identifier from the reused token row, when known. */
  sessionId?: string;
};

/**
 * Thrown when a refresh token is presented after it has already been rotated (reuse detection),
 * or when a rotate transaction is canceled under reuse-safe conditions.
 *
 * When `subjectId` / `sessionId` are present, callers can revoke the whole session
 * (e.g. via {@link RefreshTokenStore.revokeSession}) per OAuth 2.0 BCP family revocation.
 * If the store was constructed with `revokeSessionOnReuse: true`, the session may already
 * have been revoked before this error is thrown.
 */
export class DynamodbRefreshTokenProviderReusedError extends DynamodbRefreshTokenProviderError {
  override readonly name: string = 'DynamodbRefreshTokenProviderReusedError';

  /** Subject identifier from the reused token row, when known. */
  readonly subjectId?: string;

  /** Session identifier from the reused token row, when known. */
  readonly sessionId?: string;

  /**
   * @param message - Human-readable error description.
   * @param context - Subject/session from the store row to support session-wide revocation.
   */
  constructor(
    message = 'This refresh token has already been rotated and cannot be used again.',
    context?: DynamodbRefreshTokenProviderReusedErrorContext,
  ) {
    super(message);
    Object.setPrototypeOf(this, DynamodbRefreshTokenProviderReusedError.prototype);
    this.subjectId = context?.subjectId;
    this.sessionId = context?.sessionId;
  }
}

/**
 * Rotation failed for a reason other than reuse (for example a transient store failure).
 * {@link DynamodbRefreshTokenProvider.rotate} does not throw this class; those failures propagate as the original error.
 */
export class DynamodbRefreshTokenProviderRotateFailedError extends DynamodbRefreshTokenProviderError {
  override readonly name: string = 'DynamodbRefreshTokenProviderRotateFailedError';

  /**
   * @param message - Human-readable error description.
   */
  constructor(
    message = 'The refresh token could not be rotated. Please try signing in again.',
  ) {
    super(message);
    Object.setPrototypeOf(this, DynamodbRefreshTokenProviderRotateFailedError.prototype);
  }
}
