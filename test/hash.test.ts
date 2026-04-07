import crypto from 'crypto';

import { randomtoken, sha256hex } from '../src';

describe('sha256hex', () => {
  it('should return lowercase hex digest of input', () => {
    expect(sha256hex('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
    expect(sha256hex('hello')).toBe(
      '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
    );
  });
});

describe('randomtoken', () => {
  it('should return base64url string of expected length for default byte count', () => {
    const token = randomtoken();
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(token.length).toBe(Math.ceil((32 * 8) / 6));
  });

  it('should use cryptographically secure random bytes', () => {
    const spy = jest.spyOn(crypto, 'randomBytes');
    randomtoken(16);
    expect(spy).toHaveBeenCalledWith(16);
    spy.mockRestore();
  });
});
