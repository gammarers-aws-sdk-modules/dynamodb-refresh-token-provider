/** Milliseconds in one second. */
const MILLISECONDS_PER_SECOND = 1000;

/**
 * Converts a JavaScript `Date` to Unix time in whole seconds (floor).
 *
 * @param date - Instant to convert.
 * @returns Seconds since the Unix epoch.
 */
export const epochSec = (date: Date): number => {
  return Math.floor(date.getTime() / MILLISECONDS_PER_SECOND);
};
