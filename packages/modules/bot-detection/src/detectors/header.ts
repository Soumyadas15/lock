import { BotDetectionResult } from '../types';

export interface HeadersConfig {
  enabled: boolean;
  required?: string[];
  suspicious?: Record<string, string[]>;
  checkBrowserFingerprint?: boolean;
}

/**
 * Checks HTTP headers for indicators of bot activity.
 *
 * This function examines the request headers based on the provided configuration. It normalizes header names,
 * verifies the presence of required headers, detects suspicious header values, checks for inconsistencies in
 * browser fingerprinting, and evaluates common browser header patterns to determine if the request is likely
 * coming from a bot.
 *
 * @param {Record<string, string | string[] | undefined>} headers - HTTP headers from the request.
 * @param {HeadersConfig} config - Configuration for header checking, including required and suspicious headers.
 * @returns {BotDetectionResult} - An object indicating if a bot is detected, along with the detection reason,
 *                                 method, and a timestamp.
 */
export function checkHeaders(
  headers: Record<string, string | string[] | undefined>,
  config: HeadersConfig
): BotDetectionResult {
  if (!headers) {
    return {
      isBot: true,
      reason: 'No headers present',
      detectionMethod: 'headers-missing',
      timestamp: Date.now(),
    };
  }

  const normalizedHeaders: Record<string, string | string[]> = {};
  Object.keys(headers).forEach(key => {
    if (headers[key] !== undefined) {
      normalizedHeaders[key.toLowerCase()] = headers[key] as string | string[];
    }
  });

  const userAgent = normalizedHeaders['user-agent'] as string;
  const userAgentLower = userAgent ? userAgent.toLowerCase() : '';

  if (config.required && config.required.length > 0) {
    const missingHeaders = config.required.filter(
      header => !normalizedHeaders[header.toLowerCase()]
    );
    if (missingHeaders.length > 0) {
      return {
        isBot: true,
        reason: `Missing required headers: ${missingHeaders.join(', ')}`,
        detectionMethod: 'headers-missing',
        timestamp: Date.now(),
      };
    }
  }

  if (config.suspicious) {
    for (const [headerName, suspiciousValues] of Object.entries(config.suspicious)) {
      const headerValue = normalizedHeaders[headerName.toLowerCase()];
      if (headerValue) {
        const values = Array.isArray(headerValue) ? headerValue : [headerValue];
        for (const value of values) {
          for (const suspiciousValue of suspiciousValues) {
            if (value === suspiciousValue) {
              return {
                isBot: true,
                reason: `Suspicious value "${suspiciousValue}" in header "${headerName}"`,
                detectionMethod: 'headers-suspicious',
                timestamp: Date.now(),
              };
            }
          }
        }
      }
    }
  }

  if (userAgent) {
    if (userAgentLower.includes('chrome')) {
      const secChUa = normalizedHeaders['sec-ch-ua'] as string;
      if (
        userAgentLower.includes('chrome/9') ||
        userAgentLower.includes('chrome/10') ||
        userAgentLower.includes('chrome/11') ||
        userAgentLower.match(/chrome\/[789]\d/)
      ) {
        if (!secChUa) {
          return {
            isBot: true,
            reason: 'Modern Chrome user agent without required sec-ch-ua headers',
            detectionMethod: 'headers-inconsistency',
            timestamp: Date.now(),
          };
        }
      }
      if (secChUa) {
        if (secChUa.includes('Edge') && !userAgentLower.includes('edg')) {
          return {
            isBot: true,
            reason: 'Inconsistency between sec-ch-ua (Edge) and user-agent (Chrome)',
            detectionMethod: 'headers-inconsistency',
            timestamp: Date.now(),
          };
        }
        if (secChUa.includes('Firefox') && !userAgentLower.includes('firefox')) {
          return {
            isBot: true,
            reason: 'Inconsistency between sec-ch-ua (Firefox) and user-agent (Chrome)',
            detectionMethod: 'headers-inconsistency',
            timestamp: Date.now(),
          };
        }
      }
    }
    if (userAgentLower.includes('firefox/')) {
      if (!normalizedHeaders['accept-language']) {
        return {
          isBot: true,
          reason: 'Firefox user agent without accept-language header',
          detectionMethod: 'headers-inconsistency',
          timestamp: Date.now(),
        };
      }
      if (userAgentLower.match(/firefox\/[789]\d/) && !normalizedHeaders['dnt']) {
        return {
          isBot: true,
          reason: 'Modern Firefox user agent without DNT header capability',
          detectionMethod: 'headers-inconsistency',
          timestamp: Date.now(),
        };
      }
    }
  }

  const hasAcceptLanguage = !!normalizedHeaders['accept-language'];
  const hasAcceptEncoding = !!normalizedHeaders['accept-encoding'];
  const hasUserAgent = !!normalizedHeaders['user-agent'];
  const hasAccept = !!normalizedHeaders['accept'];
  if (hasUserAgent && (!hasAcceptLanguage || !hasAcceptEncoding || !hasAccept)) {
    return {
      isBot: true,
      reason: 'Missing standard browser headers',
      detectionMethod: 'headers-missing-standard',
      timestamp: Date.now(),
    };
  }

  const acceptHeader = normalizedHeaders['accept'] as string;
  if (acceptHeader && typeof acceptHeader === 'string') {
    if (
      acceptHeader === '*/*' &&
      !userAgentLower.includes('curl') &&
      !userAgentLower.includes('wget')
    ) {
      return {
        isBot: true,
        reason: 'Generic Accept header (*/*) without being a declared tool',
        detectionMethod: 'headers-suspicious-accept',
        timestamp: Date.now(),
      };
    }
    if (
      userAgentLower.includes('mozilla') &&
      !acceptHeader.includes('text/html') &&
      !acceptHeader.includes('application/xhtml')
    ) {
      return {
        isBot: true,
        reason: 'Browser user agent without HTML support in Accept header',
        detectionMethod: 'headers-suspicious-accept',
        timestamp: Date.now(),
      };
    }
  }

  if (normalizedHeaders['connection'] === 'close' && userAgentLower.includes('mozilla')) {
    return {
      isBot: true,
      reason: 'Browser user agent with Connection: close (typically used by bots)',
      detectionMethod: 'headers-suspicious-connection',
      timestamp: Date.now(),
    };
  }

  return { isBot: false, timestamp: Date.now() };
}
