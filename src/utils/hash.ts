import crypto from 'crypto';

/**
 * SHA-256 digest of `input` as a lowercase hexadecimal string.
 * Used so refresh tokens are not stored in plaintext in DynamoDB.
 *
 * @param input - String to hash (e.g. raw refresh token).
 * @returns 64-character hex string.
 */
export const sha256hex = (input: string): string => {
  return crypto.createHash('sha256').update(input).digest('hex');
};

/**
 * Generates an opaque URL-safe refresh token using cryptographically secure random bytes.
 *
 * @param bytes - Number of random bytes (default: 32, i.e. 256 bits).
 * @returns Base64url-encoded token string.
 */
export const randomtoken = (bytes: number = 32): string => {
  return crypto.randomBytes(bytes).toString('base64url');
};
