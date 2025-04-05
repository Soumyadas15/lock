import { describe, test, expect, beforeEach } from 'vitest';

import { RateLimitRecord, RateLimitStore } from '../src/types';
import { SecurityContext } from '@lock-sdk/core';
import { DDoSProtection } from '../src/strategies/factory';

/**
 * A simple in-memory FakeStore for testing purposes.
 */
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

describe('DDoSProtection', () => {
  let store: FakeStore;
  let ddosConfig: any;
  let context: SecurityContext;

  beforeEach(() => {
    store = new FakeStore();
    ddosConfig = {
      windowMs: 60000,
      ddosPrevention: {
        enabled: true,
        banDurationMs: 600000,
        burstThreshold: 10,
        requestRateThreshold: 20,
      },
    };

    context = {
      request: {
        headers: {
          'user-agent': 'Mozilla/5.0',
          'accept-language': 'en-US',
          accept: 'text/html',
        },
      },
    } as any;
  });

  test('should return no threat if DDoS prevention is disabled', async () => {
    ddosConfig.ddosPrevention.enabled = false;
    const ddosProtection = new DDoSProtection(ddosConfig);
    const result = await ddosProtection.analyze('127.0.0.1:foo', context, store);
    expect(result.isThreat).toBe(false);
    expect(result.level).toBe('none');
    expect(result.score).toBe(0);
  });

  test('should return no threat if not enough request history data', async () => {
    const ddosProtection = new DDoSProtection(ddosConfig);
    const result = await ddosProtection.analyze('127.0.0.1:foo', context, store);
    expect(result.isThreat).toBe(false);
    expect(result.level).toBe('none');
    expect(result.score).toBe(0);
  });

  test('should detect threat if request rate is high and intervals are consistent', async () => {
    const ddosProtection = new DDoSProtection(ddosConfig);
    const now = Date.now();
    const key = '127.0.0.1:foo';

    const record = {
      count: 1200,
      firstRequest: now - 60000,
      lastRequest: now,
      history: Array.from({ length: 1200 }, (_, i) => now - 60000 + i * 50),
    };

    await store.set(key, record);
    const result = await ddosProtection.analyze(key, context, store);
    expect(result.isThreat).toBe(true);
    expect(['medium', 'high', 'critical']).toContain(result.level);
    expect(result.score).toBeGreaterThan(0);
  });

  test('should blacklist IP if threat level is critical', async () => {
    const ddosProtection = new DDoSProtection(ddosConfig);
    const now = Date.now();
    const key = '127.0.0.1:foo';

    const baseHistory = Array.from({ length: 1500 }, (_, i) => now - 60000 + i * 40);
    const lastSecondEntries = Array.from({ length: 15 }, (_, i) => now - 1000 + i * 60);

    const record = {
      count: baseHistory.length + lastSecondEntries.length,
      firstRequest: now - 60000,
      lastRequest: now,
      history: [...baseHistory, ...lastSecondEntries],
    };

    await store.set(key, record);
    const result = await ddosProtection.analyze(key, context, store);
    expect(result.level).toBe('critical');
    expect(ddosProtection.isBlacklisted('127.0.0.1')).toBe(true);
  });

  test('should increase threat score if typical browser headers are missing', async () => {
    context.request.headers = {};
    const ddosProtection = new DDoSProtection(ddosConfig);
    const now = Date.now();
    const key = '192.168.1.1:foo';
    const record = {
      count: 15,
      firstRequest: now - 30000,
      lastRequest: now,
      history: Array.from({ length: 15 }, (_, i) => now - 30000 + i * 2000),
    };
    await store.set(key, record);
    const result = await ddosProtection.analyze(key, context, store);
    expect(result.score).toBeGreaterThanOrEqual(0.1);
  });
});
