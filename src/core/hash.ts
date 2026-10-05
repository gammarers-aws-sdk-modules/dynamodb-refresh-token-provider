import crypto from 'crypto';

/** Default random byte length for {@link randomToken} (32 → 256-bit). */
const DEFAULT_RANDOM_TOKEN_BYTES = 32;

/**
 * SHA-256 digest of `input` as a lowercase hexadecimal string.
 * Used so refresh tokens are not stored in plaintext in DynamoDB.
 *
 * @param input - String to hash (e.g. raw refresh token).
 * @returns 64-character hex string.
 */
export const sha256Hex = (input: string): string => {
  return crypto.createHash('sha256').update(input).digest('hex');
};

/**
 * Generates an opaque URL-safe refresh token using cryptographically secure random bytes.
 *
 * @param bytes - Number of random bytes (default: 32, i.e. 256 bits).
 * @returns Base64url-encoded token string.
 */
export const randomToken = (bytes: number = DEFAULT_RANDOM_TOKEN_BYTES): string => {
  return crypto.randomBytes(bytes).toString('base64url');
};
