import {
  DynamodbRefreshTokenProviderError,
  DynamodbRefreshTokenProviderExpiredError,
  DynamodbRefreshTokenProviderInvalidError,
  DynamodbRefreshTokenProviderReusedError,
  DynamodbRefreshTokenProviderRevokedError,
  DynamodbRefreshTokenProviderRotateFailedError,
  DynamodbRefreshTokenProviderValidateError,
} from '../src';

describe('refresh token errors', () => {
  it.each([
    [
      'DynamodbRefreshTokenProviderInvalidError',
      DynamodbRefreshTokenProviderInvalidError,
      'The refresh token is missing, malformed, or not recognized.',
    ],
    [
      'DynamodbRefreshTokenProviderExpiredError',
      DynamodbRefreshTokenProviderExpiredError,
      'The refresh token has expired. Please sign in again.',
    ],
    [
      'DynamodbRefreshTokenProviderRevokedError',
      DynamodbRefreshTokenProviderRevokedError,
      'The refresh token has been revoked.',
    ],
    [
      'DynamodbRefreshTokenProviderReusedError',
      DynamodbRefreshTokenProviderReusedError,
      'This refresh token has already been rotated and cannot be used again.',
    ],
    [
      'DynamodbRefreshTokenProviderRotateFailedError',
      DynamodbRefreshTokenProviderRotateFailedError,
      'The refresh token could not be rotated. Please try signing in again.',
    ],
  ] as const)('should have default message for %s', (_label, Ctor, expected) => {
    const err = new Ctor();
    expect(err).toBeInstanceOf(DynamodbRefreshTokenProviderError);
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toBe(expected);
    expect(err.name).toBe(Ctor.name);
  });

  it('should allow custom message on invalid error', () => {
    const err = new DynamodbRefreshTokenProviderInvalidError('custom');
    expect(err.message).toBe('custom');
  });

  it('should attach subjectId and sessionId on DynamodbRefreshTokenProviderReusedError', () => {
    const err = new DynamodbRefreshTokenProviderReusedError(undefined, {
      subjectId: 'sub-1',
      sessionId: 'sess-1',
    });
    expect(err.subjectId).toBe('sub-1');
    expect(err.sessionId).toBe('sess-1');
    expect(err.message).toBe(
      'This refresh token has already been rotated and cannot be used again.',
    );
  });

  it('should keep the validate error message and prototype chain', () => {
    const err = new DynamodbRefreshTokenProviderValidateError('tokenBytes must be a positive integer');
    expect(err).toBeInstanceOf(DynamodbRefreshTokenProviderError);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('DynamodbRefreshTokenProviderValidateError');
    expect(err.message).toBe('tokenBytes must be a positive integer');
  });
});
