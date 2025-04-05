import { createModule, SecurityContext } from '@lock-sdk/core';
import { registerModule } from '@lock-sdk/core';
import {
  BotDetectorConfig,
  BotDetectorEventType,
  RequestMetadata,
  BotDetectionResult,
} from './types';
import { extractIp } from './utils/extract-ip';
import { checkUserAgent } from './detectors/user-agent';
import { checkBehavior } from './detectors/behaviour';
import { checkHeaders } from './detectors/header';
import { checkFingerprint } from './detectors/fingeprint';
import { createCacheStore, BotCacheStore } from './storage';

const DEFAULT_CONFIG: Partial<BotDetectorConfig> = {
  enabled: true,
  captchaRedirectUrl: '/captcha',
  storage: 'memory',
  userAgent: {
    enabled: true,
    blockEmpty: true,
    blockedPatterns: [
      'bot',
      'crawl',
      'spider',
      'scrape',
      'headless',
      'puppeteer',
      'selenium',
      'phantom',
      'http-client',
      'python-requests',
      'go-http-client',
      'wget',
      'curl',
      'httpie',
    ],
    requiredPatterns: ['mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera'],
  },
  behavior: {
    enabled: true,
    minRequestInterval: 50,
    maxSessionRequests: 1000,
    sessionDuration: 3600000,
    checkPathPatterns: true,
  },
  headers: {
    enabled: true,
    required: ['accept', 'accept-language'],
    suspicious: {
      accept: ['*/*'],
      'accept-language': [''],
    },
    checkBrowserFingerprint: true,
  },
  fingerprinting: {
    enabled: true,
    cookieName: '__bot_fp',
    hashHeaderName: 'x-browser-fingerprint',
  },
  cache: {
    ttl: 3600000,
    size: 10000,
  },
  redirectStatusCode: 302,
  redirectMessage: 'Redirecting to captcha verification',
  includeOriginalUrl: true,
  allowQueryParamBypass: false,
  bypassParam: '_botcheck',
  bypassValue: 'bypass',
  failBehavior: 'closed',
};

let botCache: BotCacheStore | null = null;

export type BotDetectorModule = {
  check: (context: SecurityContext, config: BotDetectorConfig) => Promise<BotDetectionResult>;
  handleFailure: (context: SecurityContext, reason: string, data: any) => Promise<void>;
};

export const botDetector = createModule<BotDetectorConfig>({
  name: 'bot-detector',

  defaultConfig: DEFAULT_CONFIG,

  async check(context: SecurityContext, config: BotDetectorConfig) {
    try {
      if (config.enabled === false) {
        return { passed: true };
      }

      const req = context.request;
      if (config.allowQueryParamBypass && config.bypassParam && config.bypassValue) {
        const bypassValue = req.query?.[config.bypassParam];
        if (bypassValue === config.bypassValue) {
          return { passed: true };
        }
      }

      if (!botCache) {
        try {
          botCache = await createCacheStore(config);
        } catch (cacheError) {
          console.error(`Failed to initialize bot cache: ${(cacheError as Error).message}`);
          const { MemoryBotCacheStore } = await import('./storage');
          botCache = new MemoryBotCacheStore(config);
          await botCache.init();
        }
      }

      await botCache.prune(config.behavior?.sessionDuration || 3600000);

      const ip = extractIp(req);
      if (!ip) {
        return {
          passed: false,
          reason: BotDetectorEventType.SUSPICIOUS_BEHAVIOR,
          data: { error: 'No IP address could be extracted from the request' },
          severity: 'medium',
        };
      }

      const cachedResult = await botCache.getResult(ip);
      if (cachedResult && cachedResult.isBot) {
        const resultAge = Date.now() - (cachedResult.timestamp || 0);
        if (resultAge < 2 * 60 * 1000) {
          return {
            passed: false,
            reason: BotDetectorEventType.BOT_DETECTED,
            data: {
              ip,
              reason: cachedResult.reason,
              detectionMethod: cachedResult.detectionMethod,
            },
            severity: 'medium',
          };
        } else {
          await botCache.deleteResult(ip);
        }
      }

      let fingerprint: string | undefined;
      if (config.fingerprinting?.enabled) {
        const headerName = config.fingerprinting.hashHeaderName || 'x-browser-fingerprint';
        fingerprint = req.headers[headerName] as string;
        if (!fingerprint && config.fingerprinting.cookieName) {
          fingerprint = req.cookies?.[config.fingerprinting.cookieName];
        }
      }

      const metadata: RequestMetadata = {
        timestamp: Date.now(),
        ip,
        userAgent: req.headers['user-agent'] as string,
        path: req.url || '/',
        method: req.method || 'GET',
        headers: req.headers,
        fingerprint,
      };

      let existingRequests = (await botCache.getRequests(ip)) || [];
      existingRequests.push(metadata);
      const sessionDuration = config.behavior?.sessionDuration || 3600000;
      const validRequests = existingRequests
        .filter(r => metadata.timestamp - r.timestamp <= sessionDuration)
        .slice(-50);
      await botCache.setRequests(ip, validRequests);

      let detectionResult: BotDetectionResult = { isBot: false, timestamp: Date.now() };

      if (config.userAgent?.enabled) {
        const userAgentResult = checkUserAgent(metadata.userAgent, config.userAgent);
        if (userAgentResult.isBot) {
          detectionResult = userAgentResult;
        }
      }

      if (!detectionResult.isBot && config.behavior?.enabled) {
        const behaviorResult = checkBehavior(validRequests, config.behavior);
        if (behaviorResult.isBot) {
          detectionResult = behaviorResult;
        }
      }

      if (!detectionResult.isBot && config.headers?.enabled) {
        const headersResult = checkHeaders(req.headers, config.headers);
        if (headersResult.isBot) {
          detectionResult = headersResult;
        }
      }

      if (
        !detectionResult.isBot &&
        config.fingerprinting?.enabled &&
        config.headers?.checkBrowserFingerprint
      ) {
        const fingerprintResult = checkFingerprint(validRequests, fingerprint);
        if (fingerprintResult.isBot) {
          detectionResult = fingerprintResult;
        }
      }

      if (detectionResult.isBot) {
        detectionResult.timestamp = Date.now();
        await botCache.setResult(ip, detectionResult);
        return {
          passed: false,
          reason: BotDetectorEventType.BOT_DETECTED,
          data: {
            ip,
            reason: detectionResult.reason,
            detectionMethod: detectionResult.detectionMethod,
            score: detectionResult.score,
          },
          severity: 'medium',
        };
      } else {
        await botCache.deleteResult(ip);
      }

      return { passed: true };
    } catch (error) {
      console.error(`Unexpected error in bot-detector module:`, error);
      return {
        passed: config.failBehavior !== 'closed',
        reason: config.failBehavior === 'closed' ? BotDetectorEventType.BOT_DETECTED : undefined,
        data:
          config.failBehavior === 'closed' ? { error: 'Bot detector module failed' } : undefined,
        severity: 'medium',
      };
    }
  },

  async handleFailure(context, reason, data) {
    const config = context.data.get('bot-detector:config') as BotDetectorConfig;
    const res = context.response;
    const req = context.request;

    if (res.headersSent || res.writableEnded) {
      return;
    }

    let redirectUrl = config.captchaRedirectUrl;
    if (config.includeOriginalUrl) {
      const separator = redirectUrl.includes('?') ? '&' : '?';
      redirectUrl += `${separator}returnTo=${encodeURIComponent(req.url || '/')}`;
    }

    if (typeof res.redirect === 'function') {
      return res.redirect(config.redirectStatusCode || 302, redirectUrl);
    } else if (typeof res.status === 'function' && typeof res.setHeader === 'function') {
      res.status(config.redirectStatusCode || 302);
      res.setHeader('Location', redirectUrl);
      return res.end(config.redirectMessage || 'Redirecting to captcha verification');
    } else if (typeof res.statusCode === 'number') {
      res.statusCode = config.redirectStatusCode || 302;
      res.setHeader('Location', redirectUrl);
      return res.end(config.redirectMessage || 'Redirecting to captcha verification');
    }
  },
});

registerModule('botDetector', botDetector);

export * from './types';
export * from './utils/extract-ip';
export * from './detectors/user-agent';
export * from './detectors/header';
export * from './detectors/behaviour';
export * from './detectors/fingeprint';
export * from './storage';
