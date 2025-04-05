import { describe, it, expect, vi, beforeEach } from 'vitest';
import { payloadGuard } from '../src/index';
import type { SecurityContext } from '@lock-sdk/core';
import { PayloadGuardEventType } from '../src/types';

function createMockContext(
  parts: Partial<Record<'body' | 'query' | 'params' | 'headers', any>> = {}
): SecurityContext {
  const headers: Record<string, string> = {};
  const dataMap = new Map();

  const request = {
    body: {},
    query: {},
    params: {},
    headers: {},
    ...parts,
  };

  return {
    request,
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

describe('payloadGuard module', () => {
  let context: SecurityContext;

  beforeEach(() => {
    vi.resetAllMocks();
    context = createMockContext();
  });

  it('passes clean payloads with all detectors enabled', async () => {
    context = createMockContext({
      body: { name: 'Alice' },
      query: { id: '123' },
      params: { slug: 'home' },
      headers: { 'user-agent': 'test-agent' },
    });

    const mod = payloadGuard();
    const result = await mod.check(context);
    expect(result.passed).toBe(true);
  });

  it('detects XSS in query and blocks in block mode', async () => {
    context = createMockContext({
      query: { q: '<script>alert(1)</script>' },
    });

    const mod = payloadGuard({ detectXSS: true });
    const result = await mod.check(context);

    expect(result.passed).toBe(false);
    expect(result.event?.type).toBe(PayloadGuardEventType.XSS_DETECTED);
  });

  it('detects SQLi in params and allows in detect mode', async () => {
    context = createMockContext({
      params: { user: "' OR '1'='1" },
    });

    const mod = payloadGuard({ detectSQLi: true });
    const result = await mod.check(context);

    expect(result.passed).toBe(false);
    expect(result.event?.type).toBe(PayloadGuardEventType.SQL_INJECTION_DETECTED);
  });

  it('ignores excluded headers', async () => {
    context = createMockContext({
      headers: {
        authorization: "' OR '1'='1",
        'user-agent': "' OR '1'='1",
      },
    });

    const mod = payloadGuard({ detectSQLi: true, excludeHeaders: ['authorization'] });
    const result = await mod.check(context);

    expect(result.passed).toBe(false);
  });

  it('respects excludeFields in body', async () => {
    context = createMockContext({
      body: {
        name: "' OR '1'='1",
        token: "' OR '1'='1",
      },
    });

    const mod = payloadGuard({
      detectSQLi: true,
      excludeFields: ['token'],
    });

    const result = await mod.check(context);
    expect(result.passed).toBe(false);
  });

  it('uses cache to skip redundant checks', async () => {
    const body = { user: "' OR '1'='1" };
    context = createMockContext({ body });

    const mod = payloadGuard({
      detectSQLi: true,
      enableCaching: true,
    });

    const r1 = await mod.check(context);
    const r2 = await mod.check(context);

    expect(r1.passed).toBe(false);
    expect(r2.passed).toBe(false);
  });

  it('fails closed on internal error if failBehavior is closed', async () => {
    const mod = payloadGuard({
      detectXSS: true,
      failBehavior: 'closed',
    });

    context = createMockContext();
    context.request = null as any;

    const result = await mod.check(context);
    expect(result.passed).toBe(false);
    expect(result.event?.type).toBe(PayloadGuardEventType.GENERAL_INJECTION_DETECTED);
  });

  it('fails open on error when failBehavior is open (default)', async () => {
    const mod = payloadGuard();

    context = createMockContext();
    context.request = null as any;

    const result = await mod.check(context);
    expect(result.passed).toBe(true);
  });

  it('returns blocked response in handleFailure()', async () => {
    const mod = payloadGuard({ detectXSS: true });

    context = createMockContext({
      query: { q: '<script>alert()</script>' },
    });

    const result = await mod.check(context);

    if (!result.passed && mod.handleFailure) {
      await mod.handleFailure(context, result.event!);
    }

    expect(context.response.status).toHaveBeenCalledWith(403);
    expect(context.response.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: expect.stringContaining('blocked'),
        details: expect.objectContaining({
          reason: PayloadGuardEventType.XSS_DETECTED,
        }),
      })
    );
  });
});
