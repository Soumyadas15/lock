import { describe, expect, it } from 'vitest';
import { checkUserAgent } from '../src/detectors/user-agent';
import { BotDetectionResult } from '../src/types';

const defaultConfig = {
  enabled: true,
  blockEmpty: true,
  blockedPatterns: ['bot', 'crawl'],
  requiredPatterns: ['mozilla', 'chrome'],
};

describe('checkUserAgent', () => {
  it('should detect an empty user agent as bot', () => {
    const result: BotDetectionResult = checkUserAgent('', defaultConfig);
    expect(result.isBot).toBe(true);
    expect(result.reason).toContain('Empty user agent');
  });

  it('should detect user agents with blocked patterns', () => {
    const result: BotDetectionResult = checkUserAgent(
      'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
      defaultConfig
    );
    expect(result.isBot).toBe(true);
    expect(result.reason).toContain('blocked pattern');
  });

  it('should detect missing required patterns', () => {
    const result: BotDetectionResult = checkUserAgent('curl/7.64.1', defaultConfig);
    expect(result.isBot).toBe(true);
    expect(result.reason).toContain('does not contain any required patterns');
  });

  it('should pass a legitimate user agent', () => {
    const legitimateUA =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36';
    const result: BotDetectionResult = checkUserAgent(legitimateUA, defaultConfig);
    expect(result.isBot).toBe(false);
  });

  it('should flag inconsistent browser identifiers', () => {
    const inconsistentUA =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/90.0.4430.212 Safari/537.36';
    const result: BotDetectionResult = checkUserAgent(inconsistentUA, defaultConfig);
    expect(result.isBot).toBe(true);
    expect(result.reason).toContain('Inconsistent browser identifiers');
  });
});
