import type { TokenRecord } from './types';

/**
 * Token row fields that rotation reads and validates.
 *
 * `ttl` and `createdAt` are excluded because rows written before `ttl` was introduced may lack them.
 */
export type LoadedTokenRecord = Pick<
  TokenRecord,
'pk' | 'subjectId' | 'sessionId' | 'expiresAt' | 'rotatedAt' | 'revokedAt' | 'subjectGeneration'
>;

/**
 * Whether `value` is absent, `null`, or a number.
 *
 * @param value - Attribute value read from DynamoDB.
 * @returns `true` when the value is `undefined`, `null`, or a number.
 */
const isOptionalNumber = (value: unknown): boolean =>
  value === undefined || value === null || typeof value === 'number';

/**
 * Whether a DynamoDB item has the fields rotation depends on with the expected types.
 *
 * @param item - Item returned by `GetItem` (unmarshalled).
 * @returns `true` when `pk`, `subjectId`, and `sessionId` are strings, `expiresAt` is a number,
 *   and `rotatedAt`, `revokedAt`, and `subjectGeneration` are absent, `null`, or numbers.
 */
export const isLoadedTokenRecord = (item: Record<string, unknown>): item is LoadedTokenRecord =>
  typeof item.pk === 'string'
  && typeof item.subjectId === 'string'
  && typeof item.sessionId === 'string'
  && typeof item.expiresAt === 'number'
  && isOptionalNumber(item.rotatedAt)
  && isOptionalNumber(item.revokedAt)
  && isOptionalNumber(item.subjectGeneration);
