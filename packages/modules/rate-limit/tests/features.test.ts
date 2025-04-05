import { describe, it, expect, beforeEach, vi } from 'vitest';
import { rateLimit } from '../src/index';
import type { RateLimitConfig, RateLimitStrategy } from '../src/types';
import { SecurityContext } from '@lock-sdk/core';

const strategies: RateLimitStrategy[] = [
  'fixed-window',
  'sliding-window',
  'token-bucket',
  'leaky-bucket',
  'adaptive',
];

function createMockContext(): SecurityContext {
  const headers: Record<string, string> = {};
  const dataMap = new Map();

  return {
    request: {
      url: '/api/test',
      headers: {
        'x-user-id': '123',
        'x-forwarded-for': '1.2.3.4',
      },
    },
    response: {
      setHeader: (k: string, v: string) => {
        headers[k] = v;
      },
      get headers() {
        return headers;
      },
      statusCode: 200,
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
      end: vi.fn(),
      writableEnded: false,
      headersSent: false,
    },
    data: {
      set: dataMap.set.bind(dataMap),
      get: dataMap.get.bind(dataMap),
    },
  } as unknown as SecurityContext;
}

describe('RateLimit Module', () => {
  let context: SecurityContext;

  beforeEach(() => {
    context = createMockContext();
  });

  it('applies default config (fixed-window, memory)', async () => {
    const mod = rateLimit();
    const result = await mod.check(context);
    expect(result.passed).toBe(true);
  });

  it('respects custom limit and window', async () => {
    const config: RateLimitConfig = {
      limit: 2,
      windowMs: 1000,
      headers: true,
      standardHeaders: true,
    };
    const mod = rateLimit(config);
    const result1 = await mod.check(context);
    const result2 = await mod.check(context);
    const result3 = await mod.check(context);

    expect(result1.passed).toBe(true);
    expect(result2.passed).toBe(true);
    expect(result3.passed).toBe(false);
  });

  it('supports different strategies', async () => {
    for (const strategy of strategies) {
      const mod = rateLimit({ strategy, limit: 1, windowMs: 1000 });
      const result = await mod.check(context);
      expect(result.passed).toBe(true);
    }
  });

  it('respects route-specific resources config', async () => {
    const mod = rateLimit({
      limit: 100,
      windowMs: 60000,
      resources: {
        '/api/test': { limit: 1, windowMs: 1000 },
      },
    });
    const result1 = await mod.check(context);
    const result2 = await mod.check(context);
    expect(result1.passed).toBe(true);
    expect(result2.passed).toBe(false);
  });

  it('applies country-specific limits', async () => {
    const mod = rateLimit({
      limit: 100,
      windowMs: 60000,
      geoProvider: { type: 'ipapi' },
      countryLimits: {
        ZZ: { limit: 1, windowMs: 1000 },
      },
    });
    context.data.set('geo-block:country', 'ZZ');

    const r1 = await mod.check(context);
    const r2 = await mod.check(context);

    expect(r1.passed).toBe(true);
    expect(r2.passed).toBe(false);
  });

  it('uses custom key generator', async () => {
    const mod = rateLimit({
      limit: 1,
      windowMs: 1000,
      keyGenerator: async () => 'custom-user',
    });
    const r1 = await mod.check(context);
    const r2 = await mod.check(context);
    expect(r1.passed).toBe(true);
    expect(r2.passed).toBe(false);
  });

  it('skips rate limit if skipFunction returns true', async () => {
    const mod = rateLimit({
      limit: 1,
      windowMs: 1000,
      skipFunction: async () => true,
    });
    const r = await mod.check(context);
    expect(r.passed).toBe(true);
  });

  it('includes headers when enabled', async () => {
    const mod = rateLimit({
      limit: 1,
      windowMs: 1000,
      headers: true,
      standardHeaders: true,
    });
    await mod.check(context);
    expect(context.response.headers['X-RateLimit-Limit']).toBe('1');
    expect(context.response.headers['RateLimit-Limit']).toBe('1');
  });

  it('triggers DDoS protection', async () => {
    const mod = rateLimit({
      limit: 10,
      windowMs: 60000,
      ddosPrevention: {
        enabled: true,
        requestRateThreshold: 0,
        burstThreshold: 0,
        banDurationMs: 10000,
      },
    });
    const result = await mod.check(context);
    expect(result.passed).toBe(false);
    expect(result.event?.type).toBe('ddos.protection.triggered');
  });

  it('uses memory storage with custom options', async () => {
    const mod = rateLimit({
      limit: 1,
      windowMs: 1000,
      storage: 'memory',
      memoryOptions: {
        max: 1,
        ttl: 1000,
      },
    });
    const r1 = await mod.check(context);
    const r2 = await mod.check(context);
    expect(r1.passed).toBe(true);
    expect(r2.passed).toBe(false);
  });

  it('returns custom message and statusCode on block', async () => {
    const mod = rateLimit({
      limit: 1,
      windowMs: 1000,
      statusCode: 499,
      message: 'Custom limit hit',
    });
    await mod.check(context);
    const result = await mod.check(context);

    if (!result.passed && mod.handleFailure) {
      await mod.handleFailure(context, result.event!);
    }

    expect(context.response.status).toHaveBeenCalledWith(499);
    expect(context.response.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'Custom limit hit' })
    );
  });

  it('calls custom handler on block if defined', async () => {
    const handler = vi.fn();
    const mod = rateLimit({
      limit: 1,
      windowMs: 1000,
      handler: handler,
    });
    await mod.check(context);
    const result = await mod.check(context);

    if (!result.passed && mod.handleFailure) {
      await mod.handleFailure(context, result.event!);
    }

    expect(handler).toHaveBeenCalled();
  });
});
