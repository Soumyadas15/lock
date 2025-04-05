import { describe, test, expect } from 'vitest';
import { extractIp } from '../src/utils/extract-ip';

describe('extractIp', () => {
  const ipHeaders = ['cf-connecting-ip', 'x-forwarded-for', 'x-real-ip'];

  test('should return IP from the first matching header', () => {
    const request = {
      headers: {
        'cf-connecting-ip': '192.168.0.1',
        'x-forwarded-for': '10.0.0.1',
      },
      connection: { remoteAddress: '127.0.0.1' },
    };
    const ip = extractIp(request, ipHeaders, true);
    expect(ip).toBe('192.168.0.1');
  });

  test('should extract IP from a header when value contains multiple IPs', () => {
    const request = {
      headers: {
        'x-forwarded-for': '203.0.113.195, 70.41.3.18, 150.172.238.178',
      },
      connection: { remoteAddress: '127.0.0.1' },
    };
    const ip = extractIp(request, ipHeaders, false);
    expect(ip).toBe('203.0.113.195');
  });

  test('should fallback to remote address when headers are absent and useRemoteAddress is true', () => {
    const request = {
      headers: {},
      connection: { remoteAddress: '127.0.0.1' },
    };
    const ip = extractIp(request, ipHeaders, true);
    expect(ip).toBe('127.0.0.1');
  });

  test('should return null if no headers present and useRemoteAddress is false', () => {
    const request = {
      headers: {},
      connection: { remoteAddress: '127.0.0.1' },
    };
    const ip = extractIp(request, ipHeaders, false);
    expect(ip).toBeNull();
  });

  test('should handle missing connection property gracefully', () => {
    const request = {
      headers: {},
    };
    const ip = extractIp(request, ipHeaders, true);
    expect(ip).toBeNull();
  });
});
