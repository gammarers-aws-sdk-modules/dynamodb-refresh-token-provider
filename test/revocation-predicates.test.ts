import {
  INITIAL_SUBJECT_GENERATION,
  INITIAL_SUBJECT_GENERATION_CONDITION,
  isSessionMarker,
  isSessionRevoked,
  isSubjectMarker,
  sessionMarkerPk,
  sessionSubjectMarkerPk,
  SUBJECT_GENERATION_MATCH_CONDITION,
  subjectGenerationCondition,
  subjectMarkerGeneration,
  subjectMarkerPk,
  tokenSubjectGeneration,
} from '../src/core/revocation-predicates';

describe('revocation predicates', () => {
  it.each([
    ['sess-1', 'sess#sess-1'],
    ['', 'sess#'],
  ] as const)('sessionMarkerPk(%j) is %j', (sessionId, expected) => {
    expect(sessionMarkerPk(sessionId)).toBe(expected);
  });

  it.each([
    ['sess-1', 'sub-1', 'sess#sess-1#sub-1'],
  ] as const)('sessionSubjectMarkerPk(%j, %j) is %j', (sessionId, subjectId, expected) => {
    expect(sessionSubjectMarkerPk(sessionId, subjectId)).toBe(expected);
  });

  it.each([
    ['sub-1', 'sub#sub-1'],
  ] as const)('subjectMarkerPk(%j) is %j', (subjectId, expected) => {
    expect(subjectMarkerPk(subjectId)).toBe(expected);
  });

  it.each([
    [INITIAL_SUBJECT_GENERATION, INITIAL_SUBJECT_GENERATION_CONDITION],
    [1, SUBJECT_GENERATION_MATCH_CONDITION],
    [4, SUBJECT_GENERATION_MATCH_CONDITION],
  ] as const)('subjectGenerationCondition(%j) is %j', (generation, expected) => {
    expect(subjectGenerationCondition(generation)).toBe(expected);
  });

  it.each([
    [{}, true],
    [{ revokedAt: null }, true],
    [{ revokedAt: 10 }, true],
    [{ revokedAt: '10' }, false],
    [{ revokedAt: true }, false],
  ] as const)('isSessionMarker(%j) is %s', (item, expected) => {
    expect(isSessionMarker(item)).toBe(expected);
  });

  it.each([
    [{}, true],
    [{ generation: null }, true],
    [{ generation: 0 }, true],
    [{ generation: 2 }, true],
    [{ generation: '2' }, false],
  ] as const)('isSubjectMarker(%j) is %s', (item, expected) => {
    expect(isSubjectMarker(item)).toBe(expected);
  });

  it.each([
    [undefined, false],
    [{}, false],
    [{ revokedAt: null }, false],
    [{ revokedAt: 10 }, true],
  ] as const)('isSessionRevoked(%j) is %s', (item, expected) => {
    expect(isSessionRevoked(item)).toBe(expected);
  });

  it.each([
    [undefined, INITIAL_SUBJECT_GENERATION],
    [{}, INITIAL_SUBJECT_GENERATION],
    [{ generation: null }, INITIAL_SUBJECT_GENERATION],
    [{ generation: 0 }, 0],
    [{ generation: 3 }, 3],
  ] as const)('subjectMarkerGeneration(%j) is %s', (item, expected) => {
    expect(subjectMarkerGeneration(item)).toBe(expected);
  });

  it.each([
    [undefined, INITIAL_SUBJECT_GENERATION],
    [null, INITIAL_SUBJECT_GENERATION],
    [0, 0],
    [5, 5],
  ] as const)('tokenSubjectGeneration(%j) is %s', (generation, expected) => {
    expect(tokenSubjectGeneration(generation)).toBe(expected);
  });
});
