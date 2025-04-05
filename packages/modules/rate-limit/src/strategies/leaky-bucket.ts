import { SecurityContext } from '@lock-sdk/core';
import { RateLimitConfig, RateLimitResult, RateLimitStore } from '../types';
import { RateLimitStrategyImplementation } from '.';

/**
 * Leaky Bucket rate limiting implementation.
 * Processes requests at a fixed outflow rate with a limited bucket capacity,
 * simulating a "leaky bucket" where excess requests are discarded or delayed.
 *
 * Algorithm Overview:
 * 1. Determine the outflow rate (i.e. the rate at which requests "leak" out of the bucket)
 *    by dividing the limit by the window duration (requests per millisecond).
 * 2. Retrieve the current rate limit record from the store using the provided key.
 * 3. If no record exists:
 *    - Initialize a new record with a count of 1 (representing the first request),
 *      and set both the firstRequest and lastRequest timestamps to the current time.
 *    - Store the new record and return a successful result with the remaining capacity.
 * 4. If a record exists:
 *    - Calculate the time elapsed since the last request.
 *    - Compute the number of leaked requests based on the outflow rate and time elapsed.
 *    - Update the bucket level by subtracting the leaked requests (ensuring it does not fall below 0).
 *    - If the updated level is below the bucket capacity:
 *      - Accept the current request by incrementing the bucket count,
 *      - Update the lastRequest timestamp, store the record, and return success with the remaining capacity.
 *    - If the updated level equals or exceeds the bucket capacity:
 *      - The bucket is full, so calculate the wait time required for the bucket to leak enough requests
 *        to accommodate one new request.
 *      - Update the lastRequest timestamp, store the record, and return a rate limited result
 *        with the appropriate retry time.
 *
 * @class LeakyBucketStrategy
 * @implements {RateLimitStrategyImplementation}
 */
export class LeakyBucketStrategy implements RateLimitStrategyImplementation {
  async check(
    key: string,
    context: SecurityContext,
    config: RateLimitConfig,
    store: RateLimitStore
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const outflowRate = config.limit / config.windowMs; // requests per millisecond
    const bucketSize = config.limit;

    // Get or create record from the store
    let record = await store.get(key);

    if (!record) {
      // Initialize new record with one request in the bucket
      record = {
        count: 1,
        firstRequest: now,
        lastRequest: now,
      };
      await store.set(key, record);

      return {
        passed: true,
        remaining: bucketSize - 1,
        limit: bucketSize,
        retry: 0,
      };
    } else {
      // Calculate the number of requests that have leaked out since the last request
      const timeElapsed = now - record.lastRequest;
      const leakedRequests = timeElapsed * outflowRate;

      // Update the bucket level (ensuring it doesn't drop below 0)
      const newLevel = Math.max(0, record.count - leakedRequests);

      // Try to add the current request to the bucket if there's capacity
      if (newLevel < bucketSize) {
        record.count = newLevel + 1; // Consume capacity for the current request
        record.lastRequest = now;
        await store.set(key, record);

        return {
          passed: true,
          remaining: Math.floor(bucketSize - record.count),
          limit: bucketSize,
          retry: 0,
        };
      } else {
        // Bucket is full, calculate the wait time required for one token to leak
        const waitTime = (newLevel - bucketSize + 1) / outflowRate;
        record.lastRequest = now;
        await store.set(key, record);

        return {
          passed: false,
          remaining: 0,
          limit: bucketSize,
          retry: Math.ceil(waitTime),
          reason: 'RATE_LIMITED',
          data: { bucketSize, current: Math.ceil(newLevel) },
        };
      }
    }
  }
}
