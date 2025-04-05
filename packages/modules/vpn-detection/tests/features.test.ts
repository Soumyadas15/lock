import { describe, it, expect, vi, beforeEach } from 'vitest';
import { vpnDetector } from '../src/index';
import type { SecurityContext, SecurityEvent } from '@lock-sdk/core';
import type { VPNDetectionProviderInterface } from '../src/types';

const mockProvider: VPNDetectionProviderInterface = {
  init: vi.fn().mockResolvedValue(undefined),
  checkIp: vi.fn().mockResolvedValue(null),
};

const mockCache = {
  get: vi.fn().mockResolvedValue(null),
  set: vi.fn().mockResolvedValue(undefined),
  init: vi.fn().mockResolvedValue(undefined),
};

vi.mock('../src/providers', () => ({
  createProvider: vi.fn(() => mockProvider),
}));

vi.mock('../src/storage', () => ({
  createCacheStore: vi.fn(() => mockCache),
  MemoryVPNCacheStore: class {
    init = mockCache.init;
    get = mockCache.get;
    set = mockCache.set;
  },
}));

function createMockContext(): SecurityContext {
  const headers: Record<string, string> = {};
  const dataMap = new Map();

  return {
    request: {
      url: '/api/resource',
      headers: {
        'x-real-ip': '1.2.3.4',
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

describe('vpnDetector module', () => {
  let context: SecurityContext;

  beforeEach(() => {
    vi.clearAllMocks();
    context = createMockContext();
  });

  it('passes when no detection result is available', async () => {
    const mod = vpnDetector();
    const result = await mod.check(context);
    expect(result.passed).toBe(true);
  });

  it('blocks request when VPN is detected above threshold', async () => {
    (mockProvider.checkIp as any).mockResolvedValueOnce({
      isVpn: true,
      vpnScore: 0.9,
      isProxy: false,
      proxyScore: 0,
      isTor: false,
      torScore: 0,
      isDatacenter: false,
      datacenterScore: 0,
    });

    const mod = vpnDetector({ blockVpn: true, checkVpn: true, vpnScoreThreshold: 0.7 });
    const result = await mod.check(context);

    expect(result.passed).toBe(false);
    expect(result.event?.type).toBe('vpn.detected');
  });

  it('allows VPN below score threshold', async () => {
    (mockProvider.checkIp as any).mockResolvedValueOnce({
      isVpn: true,
      vpnScore: 0.5,
      isProxy: false,
      proxyScore: 0,
      isTor: false,
      torScore: 0,
      isDatacenter: false,
      datacenterScore: 0,
    });

    const mod = vpnDetector({ vpnScoreThreshold: 0.7 });
    const result = await mod.check(context);

    expect(result.passed).toBe(true);
  });

  it('blocks request with multiple matched signals', async () => {
    (mockProvider.checkIp as any).mockResolvedValueOnce({
      isVpn: true,
      vpnScore: 0.9,
      isProxy: true,
      proxyScore: 0.9,
      isTor: false,
      torScore: 0,
      isDatacenter: false,
      datacenterScore: 0,
    });

    const mod = vpnDetector({
      checkVpn: true,
      blockVpn: true,
      checkProxy: true,
      blockProxy: true,
      vpnScoreThreshold: 0.7,
      proxyScoreThreshold: 0.7,
    });

    const result = await mod.check(context);
    expect(result.passed).toBe(false);
    expect(result.event?.type).toContain('vpn');
  });

  it('uses cached result if available', async () => {
    mockCache.get.mockResolvedValueOnce({
      isVpn: true,
      vpnScore: 0.9,
      isProxy: false,
      proxyScore: 0,
      isTor: false,
      torScore: 0,
      isDatacenter: false,
      datacenterScore: 0,
    });

    const mod = vpnDetector({ blockVpn: true, vpnScoreThreshold: 0.7 });
    const result = await mod.check(context);

    expect(mockProvider.checkIp).not.toHaveBeenCalled();
    expect(result.passed).toBe(false);
  });

  it('fails closed when provider throws and failBehavior is closed', async () => {
    (mockProvider.checkIp as any).mockRejectedValueOnce(new Error('Provider error'));

    const mod = vpnDetector({ failBehavior: 'closed' });
    const result = await mod.check(context);

    expect(result.passed).toBe(false);
    expect(result.event?.type).toBe('vpn.error');
  });

  it('fails open when provider throws and failBehavior is open', async () => {
    (mockProvider.checkIp as any).mockRejectedValueOnce(new Error('Provider error'));

    const mod = vpnDetector({ failBehavior: 'open' });
    const result = await mod.check(context);

    expect(result.passed).toBe(true);
  });

  it('calls handleFailure with proper block message and details', async () => {
    const detectionResult = {
      isVpn: true,
      vpnScore: 0.9,
      isProxy: false,
      proxyScore: 0,
      isTor: false,
      torScore: 0,
      isDatacenter: false,
      datacenterScore: 0,
    };

    (mockProvider.checkIp as any).mockResolvedValueOnce(detectionResult);

    const mod = vpnDetector({ blockVpn: true, vpnScoreThreshold: 0.7 });
    const result = await mod.check(context);

    if (!result.passed && mod.handleFailure) {
      await mod.handleFailure(context, result.event as SecurityEvent);
    }

    expect(context.response.status).toHaveBeenCalledWith(403);
    expect(context.response.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: expect.stringContaining('VPN'),
        blocked: true,
        details: detectionResult,
      })
    );
  });
});
