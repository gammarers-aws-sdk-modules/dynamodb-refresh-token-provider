/**
 * Converts a JavaScript `Date` to Unix time in whole seconds (floor).
 *
 * @param date - Instant to convert.
 * @returns Seconds since the Unix epoch.
 */
export const epochsec = (date: Date): number => {
  return Math.floor(date.getTime() / 1000);
};
