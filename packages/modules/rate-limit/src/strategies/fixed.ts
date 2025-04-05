import { SecurityContext } from '@lock-sdk/core';
import { RateLimitConfig, RateLimitResult, RateLimitStore } from '../types';
import { RateLimitStrategyImplementation } from '.';

/**
 * Fixed Window Rate Limit Strategy Implementation
 *
 * Algorithm Overview:
 * 1. Get the current timestamp.
 * 2. Retrieve the rate limit record for the given key from the store.
 * 3. If no record exists or the current time exceeds the window duration since the first request:
 *    - Reset the window by creating a new record with the current timestamp.
 *    - Set the counter to 1 and store the record.
 *    - Allow the request and return the remaining limit.
 * 4. Otherwise, if the record exists and the window is still valid:
 *    - Increment the record count.
 *    - Calculate the elapsed time and the remaining window duration.
 *    - If the incremented count exceeds the defined limit:
 *       - Deny the request, return rate-limited response with retry time.
 *    - Otherwise:
 *       - Allow the request and update the remaining limit.
 *
 * @class FixedWindowStrategy
 * @implements {RateLimitStrategyImplementation}
 */
export class FixedWindowStrategy implements RateLimitStrategyImplementation {
  /**
   * Checks the rate limit for a given key and returns the result.
   *
   * @param {string} key - The unique key representing the request (often an IP or identifier).
   * @param {SecurityContext} context - The security context containing the request data.
   * @param {RateLimitConfig} config - The configuration object containing limit and window settings.
   * @param {RateLimitStore} store - The store instance to get, set, or increment the rate limit record.
   * @returns {Promise<RateLimitResult>} A promise that resolves with the rate limit result including status, remaining quota, limit, and retry time.
   */
  async check(
    key: string,
    context: SecurityContext,
    config: RateLimitConfig,
    store: RateLimitStore
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const windowMs = config.windowMs;
    const limit = config.limit;

    // Get or create record
    let record = await store.get(key);

    if (!record || now - record.firstRequest > windowMs) {
      // Window expired or new record, reset
      record = {
        count: 1,
        firstRequest: now,
        lastRequest: now,
      };
      await store.set(key, record);

      return {
        passed: true,
        remaining: limit - 1,
        limit: limit,
        retry: windowMs,
      };
    } else {
      // Increment existing record
      record = await store.increment(key);
      const timeElapsed = now - record.firstRequest;
      const timeRemaining = Math.max(0, windowMs - timeElapsed);

      // Check if over limit
      if (record.count > limit) {
        return {
          passed: false,
          remaining: 0,
          limit: limit,
          retry: timeRemaining,
          reason: 'RATE_LIMITED',
          data: { windowMs, limit, current: record.count },
        };
      }

      return {
        passed: true,
        remaining: Math.max(0, limit - record.count),
        limit: limit,
        retry: timeRemaining,
      };
    }
  }
}
