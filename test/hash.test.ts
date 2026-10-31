import crypto from 'crypto';

import { randomToken, sha256Hex } from '../src';
import { base64UrlLength } from '../src/core/hash';

describe('base64UrlLength', () => {
  it.each([
    [1, 2],
    [16, 22],
    [32, 43],
    [64, 86],
  ] as const)('base64UrlLength(%i) is %i', (bytes, expected) => {
    expect(base64UrlLength(bytes)).toBe(expected);
    expect(randomToken(bytes).length).toBe(expected);
  });
});

describe('sha256Hex', () => {
  it('should return lowercase hex digest of input', () => {
    expect(sha256Hex('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
    expect(sha256Hex('hello')).toBe(
      '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
    );
  });
});

describe('randomToken', () => {
  it('should return base64url string of expected length for default byte count', () => {
    const token = randomToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(token.length).toBe(Math.ceil((32 * 8) / 6));
  });

  it('should use cryptographically secure random bytes', () => {
    const spy = jest.spyOn(crypto, 'randomBytes');
    randomToken(16);
    expect(spy).toHaveBeenCalledWith(16);
    spy.mockRestore();
  });
});
