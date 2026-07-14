/**
 * Base class for refresh token store errors.
 * Use `instanceof` on concrete classes or this base for handling.
 */
export abstract class RefreshTokenError extends Error {
  /**
   * @param message - Human-readable error description.
   */
  protected constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/**
 * Thrown when the refresh token is missing, malformed, or not recognized.
 */
export class RefreshTokenInvalidError extends RefreshTokenError {
  /**
   * @param message - Human-readable error description.
   */
  constructor(
    message = 'The refresh token is missing, malformed, or not recognized.',
  ) {
    super(message);
  }
}

/**
 * Thrown when the refresh token has passed its logical expiration (`expiresAt`).
 */
export class RefreshTokenExpiredError extends RefreshTokenError {
  /**
   * @param message - Human-readable error description.
   */
  constructor(message = 'The refresh token has expired. Please sign in again.') {
    super(message);
  }
}

/**
 * Thrown when the refresh token has been explicitly revoked.
 */
export class RefreshTokenRevokedError extends RefreshTokenError {
  /**
   * @param message - Human-readable error description.
   */
  constructor(message = 'The refresh token has been revoked.') {
    super(message);
  }
}

/**
 * Optional identifiers attached when refresh token reuse is detected, so callers can
 * revoke the whole session (e.g. via {@link RefreshTokenStore.revokeSession}).
 */
export type RefreshTokenReusedErrorContext = {
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
export class RefreshTokenReusedError extends RefreshTokenError {
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
    context?: RefreshTokenReusedErrorContext,
  ) {
    super(message);
    this.subjectId = context?.subjectId;
    this.sessionId = context?.sessionId;
  }
}

/**
 * Thrown when rotation fails for a reason other than reuse (e.g. transient store failure).
 */
export class RefreshTokenRotateFailedError extends RefreshTokenError {
  /**
   * @param message - Human-readable error description.
   */
  constructor(
    message = 'The refresh token could not be rotated. Please try signing in again.',
  ) {
    super(message);
  }
}
