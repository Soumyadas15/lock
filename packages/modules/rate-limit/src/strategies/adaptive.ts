import { SecurityContext } from '@lock-sdk/core';
import { RateLimitConfig, RateLimitResult, RateLimitStore } from '../types';
import { RateLimitStrategyImplementation } from '.';
import { FixedWindowStrategy } from './fixed';

/**
 * Adaptive rate limiting implementation.
 * Adjusts rate limits dynamically based on current traffic patterns and potential suspicious activity.
 *
 * Algorithm Overview:
 * 1. Check if adaptive rate limiting is enabled in the configuration; if not, fall back to the fixed window strategy.
 * 2. Retrieve the rate limit record from the store for the given key.
 *    - If no record exists, create a new record with the current timestamp and initialize the history.
 * 3. Add the current request timestamp to the record’s history.
 * 4. Calculate the number of requests within the sliding window by filtering the history based on the window duration.
 * 5. Compute the current request rate (requests per second).
 *
 * 6. Calculate burst behavior using standard deviation of request intervals:
 *    - Standard deviation (σ) measures how much the intervals between requests vary.
 *    - Formula: σ = sqrt(variance), where variance = (1/n) * Σ(xᵢ - μ)²
 *      - xᵢ = each interval between requests
 *      - μ = average interval = (Σxᵢ)/n
 *      - n = number of intervals
 *    - A lower standard deviation indicates that requests are arriving at a more uniform rate,
 *      which can be a sign of automated or bot traffic.
 *
 * 7. Based on predefined adaptive thresholds:
 *    - Adjust the effective rate limit dynamically (reduce the limit if request rate exceeds thresholds).
 *    - Set an escalation level indicating the severity (e.g., elevated, high, or extreme).
 * 8. Update the record with the current count and check if the dynamic limit is exceeded:
 *    - If exceeded, log an escalation event if appropriate, and return a rate-limited response including a retry time.
 *    - Otherwise, allow the request and return the remaining quota based on the dynamic limit.
 *
 * Importance of Standard Deviation in Adaptive Limiting:
 * Standard deviation is used here to detect burstiness or uniformity in request intervals.
 * - A low standard deviation relative to the mean interval (i.e., intervals are very consistent)
 *   may indicate automated or scripted traffic.
 * - This metric is combined with the overall request rate to decide if the limit should be lowered dynamically.
 *
 * @class AdaptiveStrategy
 * @implements {RateLimitStrategyImplementation}
 */
export class AdaptiveStrategy implements RateLimitStrategyImplementation {
  async check(
    key: string,
    context: SecurityContext,
    config: RateLimitConfig,
    store: RateLimitStore
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const baseLimit = config.limit;
    const windowMs = config.windowMs;

    if (!config.adaptive || !config.adaptive.enabled) {
      return new FixedWindowStrategy().check(key, context, config, store);
    }

    let record = await store.get(key);

    if (!record) {
      record = {
        count: 1,
        firstRequest: now,
        lastRequest: now,
        history: [now],
      };
      await store.set(key, record);

      return {
        passed: true,
        remaining: baseLimit - 1,
        limit: baseLimit,
        retry: 0,
      };
    }

    await store.addToHistory?.(key, now);

    const windowStartTime = now - windowMs;
    const recentHistory = (await store.getWindowHistory?.(key, windowStartTime)) || [];

    const requestCount = recentHistory.length;
    const requestRatePerSecond = (requestCount / windowMs) * 1000;

    let burstScore = 0;
    if (recentHistory.length > 1) {
      const intervals: number[] = [];
      const sortedHistory = [...recentHistory].sort((a, b) => a - b);

      for (let i = 1; i < sortedHistory.length; i++) {
        intervals.push(sortedHistory[i] - sortedHistory[i - 1]);
      }

      // average interval (μ)
      const avgInterval = intervals.reduce((sum, val) => sum + val, 0) / intervals.length;
      // variance = (1/n) * Σ(xᵢ - μ)²
      const variance =
        intervals.reduce((sum, val) => sum + Math.pow(val - avgInterval, 2), 0) / intervals.length;
      // standard deviation (σ) = sqrt(variance)
      const stdDev = Math.sqrt(variance);

      burstScore = avgInterval > 0 ? stdDev / avgInterval : 0;
    }

    let dynamicLimit = baseLimit;
    let escalationLevel = 'normal';

    if (requestRatePerSecond > config.adaptive.thresholds.extreme) {
      dynamicLimit = Math.floor(baseLimit / 10); // 90% reduction
      escalationLevel = 'extreme';
    } else if (requestRatePerSecond > config.adaptive.thresholds.high) {
      dynamicLimit = Math.floor(baseLimit / 4); // 75% reduction
      escalationLevel = 'high';
    } else if (requestRatePerSecond > config.adaptive.thresholds.elevated) {
      dynamicLimit = Math.floor(baseLimit / 2); // 50% reduction
      escalationLevel = 'elevated';
    }

    // Update record with the current count and last request timestamp
    record.count = requestCount;
    record.lastRequest = now;
    await store.set(key, record);

    // Check if the dynamic limit is exceeded
    if (requestCount > dynamicLimit) {
      // If this is the first time hitting the threshold, log an escalation event by setting ddosScore
      const isEscalation =
        escalationLevel !== 'normal' && (!record.ddosScore || record.ddosScore < 1);

      if (isEscalation) {
        record.ddosScore = 1;
        await store.set(key, record);
      }

      return {
        passed: false,
        remaining: 0,
        limit: dynamicLimit,
        retry: Math.ceil(windowMs / dynamicLimit),
        reason: isEscalation ? 'RATE_LIMIT_ADAPTIVE_ESCALATION' : 'RATE_LIMITED',
        data: {
          dynamicLimit,
          baseLimit,
          current: requestCount,
          escalationLevel,
          requestRate: requestRatePerSecond.toFixed(2),
          burstScore: burstScore.toFixed(2),
        },
      };
    }

    return {
      passed: true,
      remaining: Math.max(0, dynamicLimit - requestCount),
      limit: dynamicLimit,
      retry: 0,
    };
  }
}
