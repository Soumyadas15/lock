import { BotDetectionResult } from '../types';

export interface UserAgentConfig {
  enabled: boolean;
  blockEmpty: boolean;
  blockedPatterns: string[];
  requiredPatterns?: string[];
}

export function checkUserAgent(
  userAgent: string | undefined,
  config: UserAgentConfig
): BotDetectionResult {
  if ((!userAgent || userAgent.trim() === '') && config.blockEmpty) {
    return {
      isBot: true,
      reason: 'Empty user agent',
      detectionMethod: 'user-agent',
      timestamp: Date.now(),
    };
  }

  if (userAgent) {
    const userAgentLower = userAgent.toLowerCase();

    for (const pattern of config.blockedPatterns) {
      if (userAgentLower.includes(pattern.toLowerCase())) {
        return {
          isBot: true,
          reason: `User agent contains blocked pattern: ${pattern}`,
          detectionMethod: 'user-agent',
          timestamp: Date.now(),
        };
      }
    }

    if (config.requiredPatterns && config.requiredPatterns.length > 0) {
      const hasRequiredPattern = config.requiredPatterns.some(pattern =>
        userAgentLower.includes(pattern.toLowerCase())
      );
      if (!hasRequiredPattern) {
        return {
          isBot: true,
          reason: 'User agent does not contain any required patterns',
          detectionMethod: 'user-agent',
          timestamp: Date.now(),
        };
      }
    }

    if (
      (userAgentLower.includes('chrome/') && !userAgentLower.includes('webkit')) ||
      (userAgentLower.includes('firefox/') && !userAgentLower.includes('gecko')) ||
      (userAgentLower.includes('safari/') && !userAgentLower.includes('webkit'))
    ) {
      return {
        isBot: true,
        reason: 'Inconsistent browser identifiers in user agent',
        detectionMethod: 'user-agent-inconsistency',
        timestamp: Date.now(),
      };
    }

    if (userAgent.length < 20 && !userAgentLower.includes('bot')) {
      return {
        isBot: true,
        reason: 'Suspiciously short user agent',
        detectionMethod: 'user-agent-length',
        timestamp: Date.now(),
      };
    }

    const automationKeys = [
      'phantomjs',
      'wkhtmlto',
      'jsdom',
      'nightmare',
      'electron',
      'webdriver',
      'playwright',
      'cypress',
      'automation',
      'script',
      'automated',
      'scraper',
    ];

    for (const key of automationKeys) {
      if (userAgentLower.includes(key)) {
        return {
          isBot: true,
          reason: `User agent contains automation identifier: ${key}`,
          detectionMethod: 'user-agent-automation',
          timestamp: Date.now(),
        };
      }
    }
  }

  return { isBot: false, timestamp: Date.now() };
}
