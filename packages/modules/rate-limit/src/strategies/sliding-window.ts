import { SecurityContext } from '@lock-sdk/core';
import { RateLimitConfig, RateLimitResult, RateLimitStore } from '../types';
import { RateLimitStrategyImplementation } from '.';

/**
 * Sliding Window rate limiting implementation.
 * More accurate counting of requests in a rolling time window.
 *
 * Algorithm Overview:
 * 1. Obtain the current timestamp and compute the start of the sliding window (now - windowMs).
 * 2. Retrieve the current rate limit record from the store using the provided key.
 * 3. If no record exists:
 *    - Create a new record with:
 *      - count set to 1,
 *      - firstRequest and lastRequest set to the current timestamp,
 *      - history array initialized with the current timestamp.
 *    - Save the new record in the store and return a successful rate limit result.
 * 4. If a record exists:
 *    - Ensure the record has a history array.
 *    - Append the current timestamp to the history and update lastRequest.
 *    - Filter the history array to include only timestamps within the sliding window.
 *    - Update the record count based on the filtered history.
 *    - Save the updated record back to the store.
 * 5. Determine if the request count exceeds the configured limit:
 *    - If the count exceeds the limit, compute the retry time based on the oldest timestamp in the window,
 *      then return a failure response with the reason "RATE_LIMITED" and the computed retry time.
 *    - Otherwise, return a successful response including the remaining request count and the retry time.
 *
 * @class SlidingWindowStrategy
 * @implements {RateLimitStrategyImplementation}
 */
export class SlidingWindowStrategy implements RateLimitStrategyImplementation {
  async check(
    key: string,
    context: SecurityContext,
    config: RateLimitConfig,
    store: RateLimitStore
  ): Promise<RateLimitResult> {
    console.log(`[SlidingWindow] Checking key: ${key}`);
    const now = Date.now();
    const windowMs = config.windowMs;
    const limit = config.limit;
    const windowStartTime = now - windowMs;

    // Get current record from the store
    let record = await store.get(key);

    // If no record exists, initialize a new record
    if (!record) {
      record = {
        count: 1, // First request in this window
        firstRequest: now,
        lastRequest: now,
        history: [now], // Start history with current request timestamp
      };
      console.log(`[SlidingWindow] New record created with count=${record.count}`);
      await store.set(key, record);

      return {
        passed: true,
        remaining: limit - 1,
        limit: limit,
        retry: windowMs,
      };
    }

    // Ensure history exists
    if (!record.history) {
      record.history = [];
    }

    // Add current request timestamp to history and update lastRequest
    record.history.push(now);
    record.lastRequest = now;

    // Filter history to include only requests within the sliding window
    const windowHistory = record.history.filter(time => time >= windowStartTime);
    const count = windowHistory.length;

    // Update record with the filtered history and count
    record.count = count;
    record.history = windowHistory; // Purge old timestamps to prevent unbounded growth
    await store.set(key, record);

    // Check if the number of requests exceeds the limit
    if (count > limit) {
      // Calculate the reset time based on the oldest request in the window
      const oldestRequest = Math.min(...windowHistory);
      const resetTime = oldestRequest + windowMs - now;

      console.log(`[SlidingWindow] Rate limit exceeded. Count=${count}, Limit=${limit}`);

      return {
        passed: false,
        remaining: 0,
        limit: limit,
        retry: resetTime > 0 ? resetTime : 1000, // Minimum retry time of 1 second
        reason: 'RATE_LIMITED',
        data: { windowMs, limit, current: count },
      };
    }

    // Return successful rate limit result with remaining quota
    return {
      passed: true,
      remaining: Math.max(0, limit - count),
      limit: limit,
      retry: windowMs,
    };
  }
}
