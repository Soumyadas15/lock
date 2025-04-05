import { SecurityContext } from '@lock-sdk/core';
import { RateLimitConfig, RateLimitStore } from '../types';
import {
  FixedWindowStrategy,
  SlidingWindowStrategy,
  TokenBucketStrategy,
  LeakyBucketStrategy,
  AdaptiveStrategy,
  RateLimitStrategyImplementation,
} from './index';

export function createStrategy(config: RateLimitConfig): RateLimitStrategyImplementation {
  const strategyType = config.strategy || 'fixed-window';

  switch (strategyType) {
    case 'sliding-window':
      return new SlidingWindowStrategy();

    case 'token-bucket':
      return new TokenBucketStrategy();

    case 'leaky-bucket':
      return new LeakyBucketStrategy();

    case 'adaptive':
      return new AdaptiveStrategy();

    case 'fixed-window':
    default:
      return new FixedWindowStrategy();
  }
}

/**
 * @class DDoSProtection
 */
export class DDoSProtection {
  private blacklist: Map<string, number> = new Map();

  private enabled: boolean;
  private requestRateThreshold: number;
  private burstThreshold: number;
  private banDurationMs: number;
  private windowMs: number;

  // Pre-allocate threat level thresholds
  private readonly CRITICAL_THRESHOLD = 0.8;
  private readonly HIGH_THRESHOLD = 0.6;
  private readonly MEDIUM_THRESHOLD = 0.4;
  private readonly LOW_THRESHOLD = 0.2;

  constructor(private config: RateLimitConfig) {
    this.enabled = !!config.ddosPrevention?.enabled;
    this.requestRateThreshold = config.ddosPrevention?.requestRateThreshold || 20;
    this.burstThreshold = config.ddosPrevention?.burstThreshold || 10;
    this.banDurationMs = config.ddosPrevention?.banDurationMs || 600000;
    this.windowMs = config.windowMs || 60000;
  }

  /**
   * Fast check to determine if IP is a known threat
   * This is a quick first-pass filter before more expensive analysis
   */
  isKnownThreat(ip: string): { isThreat: boolean; level?: string; banDuration?: number } {
    if (!this.enabled) {
      return { isThreat: false };
    }

    // Check if IP is blacklisted (fastest check)
    if (this.isBlacklisted(ip)) {
      return {
        isThreat: true,
        level: 'critical',
        banDuration: this.banDurationMs,
      };
    }

    return { isThreat: false };
  }

  /**
   * Employ early exit
   */
  async analyze(
    key: string,
    context: SecurityContext,
    store: RateLimitStore
  ): Promise<{
    isThreat: boolean;
    level: 'none' | 'low' | 'medium' | 'high' | 'critical';
    score: number;
    banDuration?: number;
  }> {
    // Early exit for disabled protection
    if (!this.enabled) {
      return { isThreat: false, level: 'none', score: 0 };
    }

    const ip = key.includes(':') ? key.substring(0, key.indexOf(':')) : key;

    // Fast path for known threats
    const knownThreat = this.isKnownThreat(ip);
    if (knownThreat.isThreat) {
      return {
        isThreat: true,
        level: 'critical' as any,
        score: 1,
        banDuration: this.banDurationMs,
      };
    }

    // Get only what we need from store (minimizing data transfer)
    const now = Date.now();
    const windowStartTime = now - this.windowMs;

    // Parallel fetching of record and history
    const [record, recentHistory] = await Promise.all([
      store.get(key),
      store.getWindowHistory?.(key, windowStartTime) || Promise.resolve([]),
    ]);

    // Early exit for insufficient data (fast path)
    const historyLength = recentHistory.length;
    if (!record || historyLength < 5) {
      return { isThreat: false, level: 'none', score: 0 };
    }

    // Fast threat scoring using bitwise integer math where possible
    let threatScore = 0;

    // Tier 1: Rate analysis (most important signal)
    // integer division for performance
    const requestRate = historyLength / (this.windowMs / 1000);
    if (requestRate > this.requestRateThreshold) {
      const rateScore = Math.min(0.4, (requestRate / this.requestRateThreshold) * 0.4);
      threatScore += rateScore;

      // Early exit optimization - if rate is very low, no need to check other factors
      if (requestRate < this.requestRateThreshold * 0.5) {
        return {
          isThreat: false,
          level: 'none',
          score: parseFloat(threatScore.toFixed(2)),
        };
      }
    }

    // Tier 2: Burst detection
    const lastSecondStartTime = now - 1000;

    // Optimize array filter with manual loop for burst detection
    // This can be 2-3x faster than .filter() for large arrays
    let lastSecondRequests = 0;
    for (let i = 0; i < historyLength; i++) {
      if (recentHistory[i] >= lastSecondStartTime) {
        lastSecondRequests++;
      }
    }

    if (lastSecondRequests > this.burstThreshold) {
      const burstScore = Math.min(0.3, (lastSecondRequests / this.burstThreshold) * 0.3);
      threatScore += burstScore;
    }

    // Only proceed with expensive calculations if we've already reached a certain threat level
    if (threatScore > 0.15) {
      // Tier 3: Interval consistency
      // Only sort if we need to
      let intervals: number[];

      let isOrdered = true;
      for (let i = 1; i < historyLength; i++) {
        if (recentHistory[i] < recentHistory[i - 1]) {
          isOrdered = false;
          break;
        }
      }

      if (isOrdered) {
        intervals = new Array(historyLength - 1);
        for (let i = 1; i < historyLength; i++) {
          intervals[i - 1] = recentHistory[i] - recentHistory[i - 1];
        }
      } else {
        // Need to sort - create efficient temp array
        const tempArray = recentHistory.slice().sort((a, b) => a - b);
        intervals = new Array(historyLength - 1);
        for (let i = 1; i < historyLength; i++) {
          intervals[i - 1] = tempArray[i] - tempArray[i - 1];
        }
      }

      if (intervals.length > 10) {
        // Calculate average interval efficiently
        let sum = 0;
        for (let i = 0; i < intervals.length; i++) {
          sum += intervals[i];
        }
        const avgInterval = sum / intervals.length;

        if (avgInterval > 0) {
          // Calculate variance efficiently
          let varianceSum = 0;
          for (let i = 0; i < intervals.length; i++) {
            const diff = intervals[i] - avgInterval;
            varianceSum += diff * diff;
          }
          const variance = varianceSum / intervals.length;
          const stdDev = Math.sqrt(variance);
          const intervalConsistency = 1 - stdDev / avgInterval;

          // Higher consistency could indicate automated/bot traffic
          if (intervalConsistency > 0.7) {
            threatScore += intervalConsistency * 0.2;
          }
        }
      }
    }

    // Tier 4: Header analysis (cheapest compute)
    const headers = context.request.headers;
    if (!(headers['user-agent'] && (headers['accept-language'] || headers['accept']))) {
      threatScore += 0.1;
    }

    // Determine threat level
    let threatLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
    if (threatScore > this.CRITICAL_THRESHOLD) {
      threatLevel = 'critical';
      // Blacklist immediately for critical threats
      this.blacklist.set(ip, now + this.banDurationMs);
    } else if (threatScore > this.HIGH_THRESHOLD) {
      threatLevel = 'high';
    } else if (threatScore > this.MEDIUM_THRESHOLD) {
      threatLevel = 'medium';
    } else if (threatScore > this.LOW_THRESHOLD) {
      threatLevel = 'low';
    } else {
      threatLevel = 'none';
    }

    return {
      isThreat: threatLevel !== 'none' && threatLevel !== 'low',
      level: threatLevel,
      score: parseFloat(threatScore.toFixed(2)),
      banDuration: threatLevel === 'critical' ? this.banDurationMs : undefined,
    };
  }

  isBlacklisted(ip: string): boolean {
    const now = Date.now();
    const expirationTime = this.blacklist.get(ip);

    if (!expirationTime) {
      return false;
    }

    if (expirationTime > now) {
      return true;
    }
    this.blacklist.delete(ip);
    return false;
  }

  getBlacklistSize(): number {
    return this.blacklist.size;
  }

  cleanBlacklist(): number {
    const now = Date.now();
    let removed = 0;

    for (const [ip, expiration] of this.blacklist.entries()) {
      if (expiration <= now) {
        this.blacklist.delete(ip);
        removed++;
      }
    }

    return removed;
  }
}
