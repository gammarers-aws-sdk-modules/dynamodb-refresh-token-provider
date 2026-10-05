/**
 * Whether a query response includes another page.
 *
 * @param exclusiveStartKey - `LastEvaluatedKey` from the page just read.
 * @returns `true` when a start key for the next page is present.
 */
export const hasNextPage = (
  exclusiveStartKey: Record<string, unknown> | undefined,
): boolean => exclusiveStartKey !== undefined;
