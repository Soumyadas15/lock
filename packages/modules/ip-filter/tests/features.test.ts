import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ipFilter } from '../src/index';
import type { IPFilterConfig } from '../src/types';
import type { SecurityContext } from '@lock-sdk/core';

vi.mock('../src/utils/extract-ip', () => ({
  extractIp: vi.fn(() => '1.2.3.4'),
}));

vi.mock('../src/utils/ip-matcher', () => ({
  isIpInList: vi.fn((ip: string, list: string[]) => list.includes(ip)),
}));

vi.mock('../src/storage', () => {
  const mockStore = {
    init: vi.fn(),
    get: vi.fn(() => null),
    set: vi.fn(),
  };
  return {
    createCacheStore: vi.fn(() => mockStore),
    MemoryIPCacheStore: vi.fn(() => mockStore),
  };
});

function createMockContext(): SecurityContext {
  const headers: Record<string, string> = {};
  const dataMap = new Map();

  return {
    request: {
      url: '/api/test',
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

describe('IP Filter Module', () => {
  let context: SecurityContext;

  const baseConfig: IPFilterConfig = {
    mode: 'blacklist',
    ipAddresses: ['1.2.3.4'],
    ipHeaders: ['x-forwarded-for'],
    useRemoteAddress: true,
    blockStatusCode: 403,
    blockMessage: 'Access denied',
    storage: 'memory',
    cacheTtl: 1000,
    cacheSize: 100,
    failBehavior: 'open',
  };

  beforeEach(() => {
    context = createMockContext();
    vi.clearAllMocks();
  });

  it('blocks blacklisted IPs', async () => {
    const mod = ipFilter(baseConfig);
    const result = await mod.check(context);
    expect(result.passed).toBe(false);
    expect(result.event?.type).toBe('ip.blocked');
  });

  it('blocks if IP is not in whitelist', async () => {
    const mod = ipFilter({ ...baseConfig, mode: 'whitelist', ipAddresses: ['8.8.8.8'] });
    const result = await mod.check(context);
    expect(result.passed).toBe(false);
    expect(result.event?.type).toBe('ip.blocked');
  });

  it('returns open on extract failure (failBehavior = open)', async () => {
    const { extractIp } = await import('../src/utils/extract-ip');
    (extractIp as any).mockReturnValueOnce(null);

    const mod = ipFilter({ ...baseConfig, failBehavior: 'open' });
    const result = await mod.check(context);
    expect(result.passed).toBe(true);
  });

  it('returns closed on extract failure (failBehavior = closed)', async () => {
    const { extractIp } = await import('../src/utils/extract-ip');
    (extractIp as any).mockReturnValueOnce(null);

    const mod = ipFilter({ ...baseConfig, failBehavior: 'closed' });
    const result = await mod.check(context);
    expect(result.passed).toBe(false);
    expect(result.event?.type).toBe('ip.blocked');
  });

  it('handleFailure returns correct JSON block response', async () => {
    const mod = ipFilter(baseConfig);
    context.data.set('ip-filter:config', baseConfig);

    const result = await mod.check(context);

    if (!result.passed && typeof mod.handleFailure === 'function') {
      await mod.handleFailure(context, result.event!);
    }

    expect(context.response.status).toHaveBeenCalledWith(403);
    expect(context.response.json).toHaveBeenCalledWith({
      error: 'Access denied',
    });
  });

  it('handleFailure skips if headers already sent', async () => {
    const mod = ipFilter(baseConfig);
    context.response.headersSent = true;

    const result = await mod.check(context);

    if (!result.passed && typeof mod.handleFailure === 'function') {
      await mod.handleFailure(context, result.event!);
    }
    expect(context.response.status).not.toHaveBeenCalled();
  });
});
