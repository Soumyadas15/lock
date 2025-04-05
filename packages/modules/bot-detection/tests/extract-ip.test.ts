import { describe, expect, it } from 'vitest';
import { extractIp, normalizeIp } from '../src/utils/extract-ip';

describe('extractIp', () => {
  it('should extract IP from x-forwarded-for header', () => {
    const req = {
      headers: {
        'x-forwarded-for': '192.168.0.1, 10.0.0.1',
      },
    };
    expect(extractIp(req)).toBe('192.168.0.1');
  });

  it('should extract IP from lowercased header name', () => {
    const req = {
      headers: {
        'x-forwarded-for': '192.168.1.1',
      },
    };
    expect(extractIp(req)).toBe('192.168.1.1');
  });

  it('should fall back to remoteAddress if headers missing', () => {
    const req = {
      headers: {},
      connection: { remoteAddress: '127.0.0.1' },
    };
    expect(extractIp(req)).toBe('127.0.0.1');
  });

  it('should return undefined if no IP is found', () => {
    const req = {
      headers: {},
    };
    expect(extractIp(req, ['x-custom-ip'], false)).toBeUndefined();
  });
});

describe('normalizeIp', () => {
  it('should remove IPv6 prefix from IPv4 addresses', () => {
    expect(normalizeIp('::ffff:127.0.0.1')).toBe('127.0.0.1');
  });

  it('should return the same IP if no IPv6 prefix is present', () => {
    expect(normalizeIp('192.168.0.1')).toBe('192.168.0.1');
  });
});
