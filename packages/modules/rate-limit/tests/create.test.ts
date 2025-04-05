import { describe, test, expect } from 'vitest';
import { createStrategy } from '../src/strategies/factory';
import { FixedWindowStrategy } from '../src/strategies/fixed';
import { SlidingWindowStrategy } from '../src/strategies/sliding-window';
import { TokenBucketStrategy } from '../src/strategies/token-bucket';
import { LeakyBucketStrategy } from '../src/strategies/leaky-bucket';
import { AdaptiveStrategy } from '../src/strategies/adaptive';
import { RateLimitConfig } from '../src/types';

describe('createStrategy', () => {
  test('should return FixedWindowStrategy if no strategy specified', () => {
    const config = {} as RateLimitConfig;
    const strategy = createStrategy(config);
    expect(strategy).toBeInstanceOf(FixedWindowStrategy);
  });

  test('should return SlidingWindowStrategy when specified', () => {
    const config = { strategy: 'sliding-window' } as RateLimitConfig;
    const strategy = createStrategy(config);
    expect(strategy).toBeInstanceOf(SlidingWindowStrategy);
  });

  test('should return TokenBucketStrategy when specified', () => {
    const config = { strategy: 'token-bucket' } as RateLimitConfig;
    const strategy = createStrategy(config);
    expect(strategy).toBeInstanceOf(TokenBucketStrategy);
  });

  test('should return LeakyBucketStrategy when specified', () => {
    const config = { strategy: 'leaky-bucket' } as RateLimitConfig;
    const strategy = createStrategy(config);
    expect(strategy).toBeInstanceOf(LeakyBucketStrategy);
  });

  test('should return AdaptiveStrategy when specified and enabled', () => {
    const config = { strategy: 'adaptive' } as RateLimitConfig;
    const strategy = createStrategy(config);
    expect(strategy).toBeInstanceOf(AdaptiveStrategy);
  });
});
