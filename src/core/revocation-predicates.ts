/** Generation stored on tokens issued before the subject has been revoked. */
export const INITIAL_SUBJECT_GENERATION = 0;

/** Amount added to the subject marker each time subject revocation runs. */
export const SUBJECT_GENERATION_STEP = 1;

/** Partition-key prefix for a session revocation marker (`sess#<sessionId>`). */
export const SESSION_MARKER_PREFIX = 'sess#';

/** Partition-key prefix for a subject generation marker (`sub#<subjectId>`). */
export const SUBJECT_MARKER_PREFIX = 'sub#';

/**
 * Condition that a session marker is not revoked.
 * Holds when the item is absent, because `revokedAt` does not exist.
 */
export const SESSION_NOT_REVOKED_CONDITION = 'attribute_not_exists(revokedAt)';

/**
 * Subject-generation condition for a token still on the initial generation.
 * An absent marker means generation 0.
 */
export const INITIAL_SUBJECT_GENERATION_CONDITION =
  'attribute_not_exists(pk) OR generation = :generation';

/**
 * Subject-generation condition for a token bound to a generation written by subject revocation.
 * The marker must exist, so a deleted row cannot make a stale token current again.
 */
export const SUBJECT_GENERATION_MATCH_CONDITION =
  'attribute_exists(pk) AND generation = :generation';

/**
 * Partition key of the session-wide revocation marker.
 *
 * @param sessionId - Session identifier.
 * @returns `sess#` plus `sessionId`.
 */
export const sessionMarkerPk = (sessionId: string): string =>
  `${SESSION_MARKER_PREFIX}${sessionId}`;

/**
 * Partition key of the revocation marker for one subject inside a session.
 *
 * @param sessionId - Session identifier.
 * @param subjectId - Subject identifier.
 * @returns `sess#<sessionId>#<subjectId>`.
 */
export const sessionSubjectMarkerPk = (sessionId: string, subjectId: string): string =>
  `${SESSION_MARKER_PREFIX}${sessionId}#${subjectId}`;

/**
 * Partition key of the subject generation marker.
 *
 * @param subjectId - Subject identifier.
 * @returns `sub#` plus `subjectId`.
 */
export const subjectMarkerPk = (subjectId: string): string =>
  `${SUBJECT_MARKER_PREFIX}${subjectId}`;

/**
 * DynamoDB condition that the subject marker still matches `generation`.
 *
 * Generation 0 accepts a missing marker. Any later generation requires the marker item,
 * so removing the row does not re-activate tokens issued under that generation.
 *
 * @param generation - Generation stored on the token being written or rotated.
 * @returns Condition expression using the `:generation` value.
 */
export const subjectGenerationCondition = (generation: number): string => {
  if (generation === INITIAL_SUBJECT_GENERATION) {
    return INITIAL_SUBJECT_GENERATION_CONDITION;
  }
  return SUBJECT_GENERATION_MATCH_CONDITION;
};

/**
 * Whether a session-marker item has a usable `revokedAt` shape.
 *
 * @param item - Unmarshalled marker item.
 * @returns `true` when `revokedAt` is absent, `null`, or a number.
 */
export const isSessionMarker = (item: Record<string, unknown>): boolean =>
  item.revokedAt === undefined || item.revokedAt === null || typeof item.revokedAt === 'number';

/**
 * Whether a subject-marker item has a usable `generation` shape.
 *
 * @param item - Unmarshalled marker item.
 * @returns `true` when `generation` is absent, `null`, or a number.
 */
export const isSubjectMarker = (item: Record<string, unknown>): boolean =>
  item.generation === undefined || item.generation === null || typeof item.generation === 'number';

/**
 * Whether the session marker records a revocation.
 *
 * @param item - Marker item, or `undefined` when the row is absent.
 * @returns `true` only when `revokedAt` is a number.
 */
export const isSessionRevoked = (item: Record<string, unknown> | undefined): boolean =>
  typeof item?.revokedAt === 'number';

/**
 * Generation currently recorded for a subject.
 *
 * @param item - Subject marker, or `undefined` when the row is absent.
 * @returns Stored generation, or {@link INITIAL_SUBJECT_GENERATION} when the row or attribute is absent.
 */
export const subjectMarkerGeneration = (item: Record<string, unknown> | undefined): number => {
  if (typeof item?.generation !== 'number') {
    return INITIAL_SUBJECT_GENERATION;
  }
  return item.generation;
};

/**
 * Generation a token row is bound to.
 *
 * @param subjectGeneration - `subjectGeneration` attribute from the token row.
 * @returns The stored number, or {@link INITIAL_SUBJECT_GENERATION} when the attribute is absent or `null`.
 */
export const tokenSubjectGeneration = (subjectGeneration: number | null | undefined): number => {
  if (typeof subjectGeneration !== 'number') {
    return INITIAL_SUBJECT_GENERATION;
  }
  return subjectGeneration;
};
