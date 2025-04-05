import { describe, test, expect } from 'vitest';
import { isIpInList } from '../src/utils/ip-matcher';

describe('isIpInList', () => {
  test('should return true if the IP exactly matches one in the list', () => {
    const ip = '192.168.1.1';
    const ipList = ['10.0.0.1', '192.168.1.1', '172.16.0.1'];
    const result = isIpInList(ip, ipList);
    expect(result).toBe(true);
  });

  test('should return false if the IP does not match any in the list', () => {
    const ip = '8.8.8.8';
    const ipList = ['10.0.0.1', '192.168.1.1', '172.16.0.1'];
    const result = isIpInList(ip, ipList);
    expect(result).toBe(false);
  });

  test('should return false for an empty IP list', () => {
    const ip = '192.168.1.1';
    const ipList: string[] = [];
    const result = isIpInList(ip, ipList);
    expect(result).toBe(false);
  });

  test('should handle IPs with extra whitespace', () => {
    const ip = ' 192.168.1.1 ';
    const ipList = ['192.168.1.1'];
    const result = isIpInList(ip.trim(), ipList);
    expect(result).toBe(true);
  });

  test('should be case insensitive if IPs are stored as strings (if applicable)', () => {
    const ip = '192.168.1.1';
    const ipList = ['192.168.1.1'];
    const result = isIpInList(ip, ipList);
    expect(result).toBe(true);
  });
});
