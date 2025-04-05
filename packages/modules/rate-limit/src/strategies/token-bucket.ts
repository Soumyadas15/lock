import { SecurityContext } from '@lock-sdk/core';
import { RateLimitConfig, RateLimitResult, RateLimitStore } from '../types';
import { RateLimitStrategyImplementation } from '.';

/**
 * Token Bucket rate limiting implementation.
 * Allows for bursts of traffic while maintaining an average rate.
 *
 * Algorithm Overview:
 * 1. Determine the refill rate in tokens per millisecond and the maximum tokens (bucket capacity)
 *    based on the configuration.
 * 2. Retrieve the current rate limit record for the given key from the store.
 * 3. If no record exists:
 *    - Initialize a new record with a full bucket (max tokens), consume one token for the current request,
 *      and save the record.
 *    - Return a successful rate limit result with the updated token count.
 * 4. If a record exists:
 *    - Calculate the number of tokens to refill based on the elapsed time since the last request.
 *    - Update the token count, ensuring it does not exceed the maximum capacity.
 *    - Attempt to consume a token:
 *      - If a token is available, deduct one token, update the request count and timestamp, then return success.
 *      - If no token is available, calculate the wait time required to generate one token,
 *        update the record, and return a failure result indicating rate limiting.
 *
 * @class TokenBucketStrategy
 * @implements {RateLimitStrategyImplementation}
 */
export class TokenBucketStrategy implements RateLimitStrategyImplementation {
  async check(
    key: string,
    context: SecurityContext,
    config: RateLimitConfig,
    store: RateLimitStore
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const refillRate = config.limit / config.windowMs; // tokens per millisecond
    const maxTokens = config.limit;

    // Get or create record
    let record = await store.get(key);

    if (!record) {
      // Initialize with full bucket and immediately consume one token for the current request
      record = {
        count: 0,
        firstRequest: now,
        lastRequest: now,
        tokens: maxTokens - 1,
      };
      await store.set(key, record);

      return {
        passed: true,
        remaining: maxTokens - 1,
        limit: maxTokens,
        retry: 0,
      };
    } else {
      // Calculate tokens to add based on the time elapsed since the last request
      const timeElapsed = now - record.lastRequest;
      const tokensToAdd = timeElapsed * refillRate;

      // Update tokens in bucket, ensuring it does not exceed the max capacity
      record.tokens = Math.min(maxTokens, (record.tokens || 0) + tokensToAdd);

      // Attempt to consume a token
      if (record.tokens >= 1) {
        record.tokens -= 1;
        record.lastRequest = now;
        record.count += 1;
        await store.set(key, record);

        return {
          passed: true,
          remaining: Math.floor(record.tokens),
          limit: maxTokens,
          retry: 0,
        };
      } else {
        // Not enough tokens: calculate the wait time for a single token to be refilled
        const timeForOneToken = (1 - record.tokens) / refillRate;
        record.lastRequest = now;
        await store.set(key, record);

        return {
          passed: false,
          remaining: 0,
          limit: maxTokens,
          retry: Math.ceil(timeForOneToken),
          reason: 'RATE_LIMITED',
          data: { maxTokens, current: 0 },
        };
      }
    }
  }
}
