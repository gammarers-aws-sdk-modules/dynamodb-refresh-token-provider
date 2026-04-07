import {
  RefreshTokenError,
  RefreshTokenExpiredError,
  RefreshTokenInvalidError,
  RefreshTokenReusedError,
  RefreshTokenRevokedError,
  RefreshTokenRotateFailedError,
} from '../src';

describe('refresh token errors', () => {
  it.each([
    ['RefreshTokenInvalidError', RefreshTokenInvalidError, 'The refresh token is missing, malformed, or not recognized.'],
    ['RefreshTokenExpiredError', RefreshTokenExpiredError, 'The refresh token has expired. Please sign in again.'],
    ['RefreshTokenRevokedError', RefreshTokenRevokedError, 'The refresh token has been revoked.'],
    [
      'RefreshTokenReusedError',
      RefreshTokenReusedError,
      'This refresh token has already been rotated and cannot be used again.',
    ],
    [
      'RefreshTokenRotateFailedError',
      RefreshTokenRotateFailedError,
      'The refresh token could not be rotated. Please try signing in again.',
    ],
  ] as const)('should have default message for %s', (_label, Ctor, expected) => {
    const err = new Ctor();
    expect(err).toBeInstanceOf(RefreshTokenError);
    expect(err.message).toBe(expected);
    expect(err.name).toBe(Ctor.name);
  });

  it('should allow custom message on invalid error', () => {
    const err = new RefreshTokenInvalidError('custom');
    expect(err.message).toBe('custom');
  });
});
