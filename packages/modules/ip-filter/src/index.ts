import { IPFilterConfig, IPFilterEventType } from './types';
import { createModule, SecurityContext } from '@lock-sdk/core';
import { registerModule } from '@lock-sdk/core';
import { extractIp } from './utils/extract-ip';
import { isIpInList } from './utils/ip-matcher';
import { createCacheStore, IPCacheStore } from './storage';

const DEFAULT_CONFIG: Partial<IPFilterConfig> = {
  mode: 'blacklist',
  ipHeaders: ['cf-connecting-ip', 'x-forwarded-for', 'x-real-ip'],
  useRemoteAddress: true,
  blockStatusCode: 403,
  blockMessage: 'Access denied based on your IP address',
  storage: 'memory',
  cacheTtl: 3600000,
  cacheSize: 10000,
  failBehavior: 'open',
};

let ipCache: IPCacheStore | null = null;

export const ipFilter = createModule<IPFilterConfig>({
  name: 'ip-filter',

  defaultConfig: DEFAULT_CONFIG,

  async check(context: SecurityContext, config: IPFilterConfig) {
    try {
      if (!ipCache) {
        try {
          ipCache = await createCacheStore(config);
        } catch (cacheError) {
          console.error(`Failed to initialize IP filter cache: ${(cacheError as Error).message}`);
          const { MemoryIPCacheStore } = await import('./storage');
          ipCache = new MemoryIPCacheStore(config);
          await ipCache.init();
        }
      }

      const ip = extractIp(context.request, config.ipHeaders, config.useRemoteAddress);

      if (!ip) {
        console.warn('No IP address could be extracted from the request');
        return {
          passed: config.failBehavior === 'open',
          reason: config.failBehavior === 'closed' ? IPFilterEventType.IP_BLOCKED : undefined,
          data: { error: 'Could not determine client IP address' },
          severity: 'medium',
        };
      }

      try {
        let cacheKey = `${ip}:${config.mode}:${config.ipAddresses.join(',')}`;
        let ipMatched = await ipCache.get(cacheKey);

        if (ipMatched === null) {
          ipMatched = isIpInList(ip, config.ipAddresses);
          await ipCache.set(cacheKey, ipMatched);
        }

        const isBlocked =
          (config.mode === 'blacklist' && ipMatched) || (config.mode === 'whitelist' && !ipMatched);

        if (isBlocked) {
          if (config.logBlocked) {
            const logFn = config.logFunction || console.log;
            logFn(`IP blocked: ${ip}`, { matched: ipMatched, mode: config.mode });
          }

          return {
            passed: false,
            reason: IPFilterEventType.IP_BLOCKED,
            data: { ip, matched: ipMatched },
            severity: 'medium',
          };
        }

        if (config.logAllowed) {
          const logFn = config.logFunction || console.log;
          logFn(`IP allowed: ${ip}`, { matched: ipMatched, mode: config.mode });
        }

        return {
          passed: true,
          reason: IPFilterEventType.IP_ALLOWED,
          data: { ip, matched: ipMatched },
          severity: 'low',
        };
      } catch (matchError) {
        console.error(`Error during IP matching for ${ip}:`, matchError);

        if (config.failBehavior === 'closed') {
          return {
            passed: false,
            reason: IPFilterEventType.IP_FILTER_ERROR,
            data: { error: 'IP matching failed', ip },
            severity: 'medium',
          };
        }
        return { passed: true };
      }
    } catch (error) {
      console.error(`Unexpected error in ip-filter module:`, error);
      return {
        passed: config.failBehavior !== 'closed',
        reason: config.failBehavior === 'closed' ? IPFilterEventType.IP_FILTER_ERROR : undefined,
        data: config.failBehavior === 'closed' ? { error: 'IP-filter module failed' } : undefined,
        severity: 'medium',
      };
    }
  },

  async handleFailure(context, reason, data) {
    const config = context.data.get('ip-filter:config') as IPFilterConfig;
    const res = context.response;

    if (res.headersSent || res.writableEnded) {
      return;
    }

    if (typeof res.status === 'function') {
      return res.status(config.blockStatusCode ?? 403).json({
        error: config.blockMessage ?? 'Access denied based on your IP address',
      });
    } else if (typeof res.statusCode === 'number') {
      res.statusCode = config.blockStatusCode ?? 403;
      res.setHeader('Content-Type', 'application/json');
      return res.end(
        JSON.stringify({
          error: config.blockMessage ?? 'Access denied based on your IP address',
        })
      );
    }
  },
});

registerModule('ipFilter', ipFilter);

export * from './types';
export * from './utils/extract-ip';
export * from './utils/ip-matcher';
export * from './storage';
