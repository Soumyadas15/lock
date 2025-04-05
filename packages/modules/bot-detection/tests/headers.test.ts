import { describe, expect, it } from 'vitest';
import { checkHeaders } from '../src/detectors/header';
import { BotDetectionResult } from '../src/types';

const config = {
  enabled: true,
  required: ['accept', 'accept-language'],
  suspicious: {
    accept: ['*/*'],
    'accept-language': [''],
  },
  checkBrowserFingerprint: true,
};

describe('checkHeaders', () => {
  it('should flag missing headers', () => {
    const headers = {
      'user-agent': 'Mozilla/5.0',
    };
    const result: BotDetectionResult = checkHeaders(headers, config);
    expect(result.isBot).toBe(true);
    expect(result.reason).toContain('Missing required headers');
  });

  it('should flag suspicious header value', () => {
    const headers = {
      'user-agent': 'Mozilla/5.0',
      accept: '*/*',
      'accept-language': 'en-US',
    };
    const result: BotDetectionResult = checkHeaders(headers, config);
    expect(result.isBot).toBe(true);
    expect(result.reason).toContain('Suspicious value');
  });

  it('should pass valid headers', () => {
    const headers = {
      'user-agent': 'Mozilla/5.0',
      accept: 'text/html,application/xhtml+xml,application/xml;q=0.9',
      'accept-language': 'en-US,en;q=0.9',
      'accept-encoding': 'gzip, deflate, br',
    };
    const result: BotDetectionResult = checkHeaders(headers, config);
    expect(result.isBot).toBe(false);
  });
});
