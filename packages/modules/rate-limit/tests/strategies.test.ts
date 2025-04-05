import { describe, test, expect } from 'vitest';
import { FixedWindowStrategy } from '../src/strategies/fixed';
import { SlidingWindowStrategy } from '../src/strategies/sliding-window';
import { TokenBucketStrategy } from '../src/strategies/token-bucket';
import { LeakyBucketStrategy } from '../src/strategies/leaky-bucket';
import { AdaptiveStrategy } from '../src/strategies/adaptive';
import { RateLimitConfig, RateLimitRecord, RateLimitStore } from '../src/types';
import { SecurityContext } from '@lock-sdk/core';

class FakeStore implements RateLimitStore {
  records = new Map<string, any>();

  async init(): Promise<void> {
    return Promise.resolve();
  }

  async get(key: string): Promise<RateLimitRecord | null> {
    return this.records.get(key) || null;
  }

  async set(key: string, record: RateLimitRecord): Promise<void> {
    this.records.set(key, record);
  }

  async increment(key: string, value: number = 1): Promise<RateLimitRecord> {
    let record = await this.get(key);
    if (record) record.count += value;
    this.records.set(key, record);
    return record!;
  }

  async reset(key: string): Promise<void> {
    this.records.delete(key);
    return Promise.resolve();
  }

  async close(): Promise<void> {
    return Promise.resolve();
  }

  async addToHistory(key: string, timestamp: number): Promise<void> {
    let record = await this.get(key);
    if (record) {
      record.history = record.history || [];
      record.history.push(timestamp);
    }
    this.records.set(key, record);
    return Promise.resolve();
  }

  async getWindowHistory(key: string, startTime: number): Promise<number[]> {
    let record = await this.get(key);
    if (!record || !record.history) return [];
    return record.history.filter((t: number) => t >= startTime);
  }
}

const baseConfig: RateLimitConfig = {
  limit: 5,
  windowMs: 60000,
};

const context: SecurityContext = {
  request: {
    headers: {
      'user-agent': 'test-agent',
      'accept-language': 'en-US',
      accept: 'text/html',
    },
  },
} as any;

describe('FixedWindowStrategy', () => {
  test('should allow first request and reset record if window expired', async () => {
    const store = new FakeStore();
    const strategy = new FixedWindowStrategy();
    const key = '127.0.0.1:test';
    const result1 = await strategy.check(key, context, baseConfig, store);
    expect(result1.passed).toBe(true);
    expect(result1.remaining).toBe(4);

    await store.set(key, {
      count: 10,
      firstRequest: Date.now() - 70000,
      lastRequest: Date.now() - 70000,
    });
    const result2 = await strategy.check(key, context, baseConfig, store);
    expect(result2.passed).toBe(true);
    expect(result2.remaining).toBe(4);
  });
});

describe('SlidingWindowStrategy', () => {
  test('should create a new record if one does not exist', async () => {
    const store = new FakeStore();
    const strategy = new SlidingWindowStrategy();
    const key = '127.0.0.1:test';
    const result = await strategy.check(key, context, baseConfig, store);
    expect(result.passed).toBe(true);
    expect(result.remaining).toBe(4);
  });

  test('should block request if request count exceeds limit', async () => {
    const store = new FakeStore();
    const strategy = new SlidingWindowStrategy();
    const key = '127.0.0.1:test';
    const now = Date.now();
    await store.set(key, {
      count: 6,
      firstRequest: now - 10000,
      lastRequest: now,
      history: [now - 10000, now - 9000, now - 8000, now - 7000, now - 6000, now - 5000],
    });
    const result = await strategy.check(key, context, baseConfig, store);
    expect(result.passed).toBe(false);
    expect(result.remaining).toBe(0);
  });
});

describe('TokenBucketStrategy', () => {
  test('should allow request if tokens are available', async () => {
    const store = new FakeStore();
    const strategy = new TokenBucketStrategy();
    const key = '127.0.0.1:test';
    const result = await strategy.check(key, context, baseConfig, store);
    expect(result.passed).toBe(true);
    expect(result.remaining).toBeGreaterThanOrEqual(0);
  });

  test('should block request if not enough tokens are available', async () => {
    const store = new FakeStore();
    const strategy = new TokenBucketStrategy();
    const key = '127.0.0.1:test';
    await store.set(key, {
      count: 1,
      firstRequest: Date.now(),
      lastRequest: Date.now(),
      tokens: 0,
    });
    const result = await strategy.check(key, context, baseConfig, store);
    expect(result.passed).toBe(false);
    expect(result.remaining).toBe(0);
    expect(result.retry).toBeGreaterThan(0);
  });
});

describe('LeakyBucketStrategy', () => {
  test('should allow request if bucket has capacity', async () => {
    const store = new FakeStore();
    const strategy = new LeakyBucketStrategy();
    const key = '127.0.0.1:test';
    const result = await strategy.check(key, context, baseConfig, store);
    expect(result.passed).toBe(true);
    expect(result.remaining).toBeGreaterThanOrEqual(0);
  });

  test('should block request if bucket is full', async () => {
    const store = new FakeStore();
    const strategy = new LeakyBucketStrategy();
    const key = '127.0.0.1:test';
    const now = Date.now();
    await store.set(key, { count: baseConfig.limit, firstRequest: now - 1000, lastRequest: now });
    const result = await strategy.check(key, context, baseConfig, store);
    expect(result.passed).toBe(false);
    expect(result.remaining).toBe(0);
    expect(result.retry).toBeGreaterThan(0);
  });
});

describe('AdaptiveStrategy', () => {
  test('should fall back to FixedWindowStrategy if adaptive is disabled', async () => {
    const store = new FakeStore();
    const strategy = new AdaptiveStrategy();
    const key = '127.0.0.1:test';
    const config = { ...baseConfig, adaptive: { enabled: false } };
    //@ts-expect-error IGNORE
    const result = await strategy.check(key, context, config, store);
    expect(result.passed).toBe(true);
    expect(result.remaining).toBe(4);
  });

  test('should adjust dynamic limit based on high request rate', async () => {
    const store = new FakeStore();
    const strategy = new AdaptiveStrategy();
    const key = '127.0.0.1:test';
    const config = {
      ...baseConfig,
      adaptive: {
        enabled: true,
        thresholds: {
          extreme: 30,
          high: 4,
          elevated: 3,
        },
      },
      windowMs: 10000,
    };

    const now = Date.now();
    const history = Array.from({ length: 50 }, (_, i) => now - 9000 + i * (9000 / 50));
    await store.set(key, {
      count: 50,
      firstRequest: now - 9000,
      lastRequest: now,
      history: history,
    });
    //@ts-expect-error
    const result = await strategy.check(key, context, config, store);
    expect(result.passed).toBe(false);
    expect(result.limit).toBeLessThan(baseConfig.limit);
  });
});
