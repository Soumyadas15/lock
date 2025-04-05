import { describe, it, expect, vi, beforeEach } from 'vitest';
import { geoBlock } from '../src/index';
import type { GeoBlockConfig } from '../src/types';
import type { SecurityContext } from '@lock-sdk/core';

vi.mock('../src/utils/extract-ip', () => ({
  extractIp: vi.fn(() => '1.2.3.4'),
}));

vi.mock('../src/providers', () => ({
  createProvider: vi.fn(() => ({
    init: vi.fn(),
    lookup: vi.fn(() => ({ country: 'US' })),
  })),
}));

vi.mock('../src/storage', () => {
  const store = {
    init: vi.fn(),
    get: vi.fn(() => null),
    set: vi.fn(),
  };
  return {
    createCacheStore: vi.fn(() => store),
    MemoryGeoCacheStore: vi.fn(() => store),
  };
});

function createMockContext(): SecurityContext {
  const headers: Record<string, string> = {};
  const dataMap = new Map();

  return {
    request: {
      url: '/geo',
      headers: {
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

describe('GeoBlock Module', () => {
  let context: SecurityContext;

  const baseConfig: GeoBlockConfig = {
    countries: ['CN'],
    mode: 'blacklist',
    ipHeaders: ['x-forwarded-for'],
    useRemoteAddress: true,
    blockStatusCode: 403,
    blockMessage: 'Access denied by country',
    provider: 'ipapi',
    storage: 'memory',
    cacheTtl: 3600000,
    cacheSize: 10000,
    failBehavior: 'open',
  };

  beforeEach(() => {
    context = createMockContext();
    vi.clearAllMocks();
  });

  it('allows IP if not in blacklist', async () => {
    const mod = geoBlock(baseConfig);
    const result = await mod.check(context);
    expect(result.passed).toBe(true);
  });

  it('blocks IP if in blacklist', async () => {
    const mod = geoBlock({
      ...baseConfig,
      countries: ['US'], // mock lookup returns US
    });
    const result = await mod.check(context);
    expect(result.passed).toBe(false);
    expect(result.event?.type).toBe('geo.blocked');
  });

  it('allows IP if in whitelist', async () => {
    const mod = geoBlock({
      ...baseConfig,
      mode: 'whitelist',
      countries: ['US'],
    });
    const result = await mod.check(context);
    expect(result.passed).toBe(true);
  });

  it('blocks IP if not in whitelist', async () => {
    const mod = geoBlock({
      ...baseConfig,
      mode: 'whitelist',
      countries: ['CN'],
    });
    const result = await mod.check(context);
    expect(result.passed).toBe(false);
  });

  it('allows when IP is missing', async () => {
    const { extractIp } = await import('../src/utils/extract-ip');
    (extractIp as any).mockReturnValueOnce(null);

    const mod = geoBlock(baseConfig);
    const result = await mod.check(context);
    expect(result.passed).toBe(true);
  });

  it('allows when geo info is missing', async () => {
    const { createProvider } = await import('../src/providers');
    (createProvider as any).mockReturnValueOnce({
      init: vi.fn(),
      lookup: vi.fn(() => null),
    });

    const mod = geoBlock(baseConfig);
    const result = await mod.check(context);
    expect(result.passed).toBe(true);
  });

  it('handleFailure skips if headers sent', async () => {
    const mod = geoBlock(baseConfig);
    context.response.headersSent = true;

    const result = await mod.check(context);

    if (!result.passed && typeof mod.handleFailure === 'function') {
      await mod.handleFailure(context, result.event!);
    }
    expect(context.response.status).not.toHaveBeenCalled();
  });
});
