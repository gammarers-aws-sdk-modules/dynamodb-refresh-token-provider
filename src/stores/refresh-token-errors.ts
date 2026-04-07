/**
 * Base class for refresh token store errors.
 * Use `instanceof` on concrete classes or this base for handling.
 */
export abstract class RefreshTokenError extends Error {
  protected constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/**
 * Thrown when the refresh token is missing, malformed, or not recognized.
 */
export class RefreshTokenInvalidError extends RefreshTokenError {
  constructor(
    message = 'The refresh token is missing, malformed, or not recognized.',
  ) {
    super(message);
  }
}

/**
 * Thrown when the refresh token has passed its expiration time.
 */
export class RefreshTokenExpiredError extends RefreshTokenError {
  constructor(message = 'The refresh token has expired. Please sign in again.') {
    super(message);
  }
}

/**
 * Thrown when the refresh token has been explicitly revoked.
 */
export class RefreshTokenRevokedError extends RefreshTokenError {
  constructor(message = 'The refresh token has been revoked.') {
    super(message);
  }
}

/**
 * Thrown when a refresh token is presented after it has already been rotated (reuse detection).
 */
export class RefreshTokenReusedError extends RefreshTokenError {
  constructor(
    message = 'This refresh token has already been rotated and cannot be used again.',
  ) {
    super(message);
  }
}

/**
 * Thrown when rotation fails for a reason other than reuse (e.g. transient store failure).
 */
export class RefreshTokenRotateFailedError extends RefreshTokenError {
  constructor(
    message = 'The refresh token could not be rotated. Please try signing in again.',
  ) {
    super(message);
  }
}
