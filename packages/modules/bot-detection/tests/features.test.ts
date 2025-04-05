import { describe, it, expect, beforeEach, vi } from 'vitest';
import { botDetector } from '../src/index';
import { BotDetectorEventType } from '../src/types';
import type { SecurityContext } from '@lock-sdk/core';

vi.mock('../src/utils/extract-ip', () => ({
  extractIp: vi.fn(() => '127.0.0.1'),
}));

vi.mock('../src/detectors/user-agent', () => ({
  checkUserAgent: vi.fn(() => ({
    isBot: true,
    reason: 'Blocked User-Agent',
    detectionMethod: 'user-agent',
    score: 0.9,
  })),
}));

vi.mock('../src/detectors/behaviour', () => ({
  checkBehavior: vi.fn(() => ({ isBot: false })),
}));

vi.mock('../src/detectors/header', () => ({
  checkHeaders: vi.fn(() => ({ isBot: false })),
}));

vi.mock('../src/detectors/fingeprint', () => ({
  checkFingerprint: vi.fn(() => ({ isBot: false })),
}));

vi.mock('../src/storage', () => {
  const mockCache = {
    prune: vi.fn(),
    getResult: vi.fn(() => null),
    setResult: vi.fn(),
    deleteResult: vi.fn(),
    getRequests: vi.fn(() => []),
    setRequests: vi.fn(),
  };
  return {
    createCacheStore: vi.fn(() => mockCache),
    MemoryBotCacheStore: vi.fn(() => mockCache),
  };
});

function createMockContext(query = {}): SecurityContext {
  const headers: Record<string, string> = {
    'user-agent': 'some-agent',
    accept: 'application/json',
    'accept-language': 'en-US',
    'x-browser-fingerprint': 'fp123',
  };

  const dataMap = new Map();

  return {
    request: {
      method: 'GET',
      url: '/test',
      query,
      headers,
      cookies: { __bot_fp: 'fp123' },
    },
    response: {
      setHeader: vi.fn(),
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
      end: vi.fn(),
      redirect: vi.fn(),
      headersSent: false,
      writableEnded: false,
      statusCode: 200,
    },
    data: {
      set: dataMap.set.bind(dataMap),
      get: dataMap.get.bind(dataMap),
    },
  } as unknown as SecurityContext;
}

describe('BotDetector Module', () => {
  let context: SecurityContext;

  beforeEach(() => {
    context = createMockContext();
    vi.clearAllMocks();
  });

  it('bypasses check via query param', async () => {
    context = createMockContext({ _botcheck: 'bypass' });

    const mod = botDetector({
      enabled: true,
      allowQueryParamBypass: true,
      bypassParam: '_botcheck',
      bypassValue: 'bypass',
      captchaRedirectUrl: '/captcha',
    });

    const result = await mod.check(context);
    expect(result.passed).toBe(true);
  });

  it('returns bot detected via user-agent', async () => {
    const mod = botDetector({ enabled: true, captchaRedirectUrl: '/captcha' });
    const result = await mod.check(context);
    expect(result.passed).toBe(false);
    expect(result.event?.type).toBe(BotDetectorEventType.BOT_DETECTED);
  });

  it('handles missing IP gracefully', async () => {
    const { extractIp } = await import('../src/utils/extract-ip');
    (extractIp as any).mockReturnValueOnce(null);

    const mod = botDetector({ enabled: true, captchaRedirectUrl: '/captcha' });
    const result = await mod.check(context);
    expect(result.passed).toBe(false);
    expect(result.event?.type).toBe(BotDetectorEventType.SUSPICIOUS_BEHAVIOR);
  });

  it('allows normal request if no detections hit', async () => {
    const { checkUserAgent } = await import('../src/detectors/user-agent');
    (checkUserAgent as any).mockReturnValueOnce({ isBot: false });

    const mod = botDetector({ enabled: true, captchaRedirectUrl: '/captcha' });
    const result = await mod.check(context);
    expect(result.passed).toBe(true);
  });
});
