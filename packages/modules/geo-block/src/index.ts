import { GeoBlockConfig, GeoBlockEventType } from './types';
import { createModule, SecurityContext } from '@lock-sdk/core';
import { createProvider } from './providers';
import { extractIp } from './utils/extract-ip';
import { registerModule } from '@lock-sdk/core';
import { createCacheStore, GeoCacheStore } from './storage';

const DEFAULT_CONFIG: Partial<GeoBlockConfig> = {
  mode: 'blacklist',
  ipHeaders: ['cf-connecting-ip', 'x-forwarded-for', 'x-real-ip'],
  useRemoteAddress: true,
  blockStatusCode: 403,
  blockMessage: 'Access denied based on your location',
  provider: 'ipapi',
  storage: 'memory',
  cacheTtl: 3600000,
  cacheSize: 10000,
  failBehavior: 'open',
};

let geoCache: GeoCacheStore | null = null;
let provider: any = null;

export const geoBlock = createModule<GeoBlockConfig>({
  name: 'geo-block',

  defaultConfig: DEFAULT_CONFIG,

  async check(context: SecurityContext, config: GeoBlockConfig) {
    try {
      if (!geoCache) {
        try {
          geoCache = await createCacheStore(config);
        } catch (cacheError) {
          console.error(`Failed to initialize geo cache: ${(cacheError as Error).message}`);
          const { MemoryGeoCacheStore } = await import('./storage');
          geoCache = new MemoryGeoCacheStore(config);
          await geoCache.init();
        }
      }

      if (!provider) {
        provider = createProvider(config);
        try {
          await provider.init();
        } catch (initError) {
          console.error(`Failed to initialize geo provider: ${(initError as Error).message}`);
          if (config.failBehavior === 'closed') {
            return {
              passed: false,
              reason: GeoBlockEventType.GEO_BLOCKED,
              data: { error: 'Geo provider failed to initialize' },
              severity: 'medium',
            };
          }

          if (config.provider !== 'ipapi') {
            try {
              const IpApiProvider = require('./providers/ip-api').IpApiProvider;
              const fallbackProvider = new IpApiProvider(config);
              await fallbackProvider.init();
              provider = fallbackProvider;
              console.warn('Successfully switched to ip-api fallback provider');
            } catch (fallbackError) {
              console.error(`Fallback provider also failed: ${(fallbackError as Error).message}`);
              return { passed: true };
            }
          } else {
            return { passed: true };
          }
        }
      }

      const ip = extractIp(context.request, config.ipHeaders, config.useRemoteAddress);
      if (!ip) {
        console.warn('No IP address could be extracted from the request');
        return { passed: true };
      }
      try {
        let geoInfo = await geoCache.get(ip);
        if (!geoInfo) {
          geoInfo = await provider.lookup(ip);
          if (geoInfo && Object.keys(geoInfo).length > 0) {
            await geoCache.set(ip, geoInfo);
          }
        }

        if (!geoInfo || !geoInfo.country) {
          console.warn(`No country information found for IP: ${ip}`);
          return { passed: true };
        }

        const country = geoInfo.country;

        context.data.set('geo-block:country', country);
        const isBlocked =
          (config.mode === 'blacklist' && config.countries.includes(country)) ||
          (config.mode === 'whitelist' && !config.countries.includes(country));

        if (isBlocked) {
          return {
            passed: false,
            reason: GeoBlockEventType.GEO_BLOCKED,
            data: { ip, country, geoInfo },
            severity: 'medium',
          };
        }

        return { passed: true };
      } catch (lookupError) {
        console.error(`Error during geo lookup for IP ${ip}:`, lookupError);
        if (config.failBehavior === 'closed') {
          return {
            passed: false,
            reason: GeoBlockEventType.GEO_BLOCKED,
            data: { error: 'Geo lookup failed', ip },
            severity: 'medium',
          };
        }
        return { passed: true };
      }
    } catch (error) {
      console.error(`Unexpected error in geo-block module:`, error);
      return {
        passed: config.failBehavior !== 'closed',
        reason: config.failBehavior === 'closed' ? GeoBlockEventType.GEO_BLOCKED : undefined,
        data: config.failBehavior === 'closed' ? { error: 'Geo-block module failed' } : undefined,
        severity: 'medium',
      };
    }
  },

  async handleFailure(context, reason, data) {
    const config = context.data.get('geo-block:config') as GeoBlockConfig;
    const res = context.response;

    if (res.headersSent || res.writableEnded) {
      return;
    }

    if (typeof res.status === 'function') {
      return res.status(config.blockStatusCode ?? 403).json({
        error: config.blockMessage ?? 'Access denied based on your location',
      });
    } else if (typeof res.statusCode === 'number') {
      res.statusCode = config.blockStatusCode ?? 403;
      res.setHeader('Content-Type', 'application/json');
      return res.end(
        JSON.stringify({
          error: config.blockMessage ?? 'Access denied based on your location',
        })
      );
    }
  },
});

registerModule('geoBlock', geoBlock);

export * from './types';
export * from './utils/extract-ip';
export * from './storage';
