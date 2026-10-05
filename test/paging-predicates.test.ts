import { hasNextPage } from '../src/core/paging-predicates';

describe('hasNextPage', () => {
  it.each([
    [undefined, false],
    [{}, true],
    [{ pk: 'rt#abc' }, true],
  ] as const)('hasNextPage(%j) is %s', (exclusiveStartKey, expected) => {
    expect(hasNextPage(exclusiveStartKey)).toBe(expected);
  });
});
