import { createModule, SecurityContext, SecurityEventType, registerModule } from '@lock-sdk/core';
import { RateLimitConfig, RateLimitEventType, RateLimitResult, RateLimitStore } from './types';
import { createStore } from './storage';
import { createStrategy, DDoSProtection } from './strategies/factory';
import { extractIp } from './utils/extract-ip';
import { createGeoProvider } from './geo';

function addRateLimitHeaders(
  context: SecurityContext,
  result: RateLimitResult,
  config: RateLimitConfig
) {
  if (!config.headers) return;

  const res = context.response;
  const remaining = result.remaining !== undefined ? result.remaining : 0;
  const limit = result.limit !== undefined ? result.limit : config.limit;
  const resetTime = result.retry ? new Date(Date.now() + result.retry).getTime() : undefined;

  if (config.standardHeaders) {
    res.setHeader(config.headerLimit || 'X-RateLimit-Limit', limit.toString());
    res.setHeader(
      config.headerRemaining || 'X-RateLimit-Remaining',
      Math.max(0, remaining).toString()
    );

    if (resetTime) {
      res.setHeader(
        config.headerReset || 'X-RateLimit-Reset',
        Math.ceil(resetTime / 1000).toString()
      );
    }
  }

  res.setHeader('RateLimit-Limit', limit.toString());
  res.setHeader('RateLimit-Remaining', Math.max(0, remaining).toString());

  if (resetTime) {
    res.setHeader('RateLimit-Reset', Math.ceil(resetTime / 1000).toString());
  }
}

const moduleStores = new Map<string, RateLimitStore>();

const DEFAULT_CONFIG: Partial<RateLimitConfig> = {
  limit: 100,
  windowMs: 60000,
  strategy: 'fixed-window',
  storage: 'memory',
  ipHeaders: ['cf-connecting-ip', 'x-forwarded-for', 'x-real-ip'],
  useRemoteAddress: true,
  headers: true,
  standardHeaders: true,
  headerLimit: 'X-RateLimit-Limit',
  headerRemaining: 'X-RateLimit-Remaining',
  headerReset: 'X-RateLimit-Reset',
  statusCode: 429,
  message: 'Too many requests, please try again later.',
  memoryOptions: {
    max: 10000,
    ttl: 3600000,
  },
  ddosPrevention: {
    enabled: false,
    requestRateThreshold: 50,
    burstThreshold: 20,
    banDurationMs: 3600000,
  },
};

export const rateLimit = createModule<RateLimitConfig>({
  name: 'rate-limit',

  defaultConfig: DEFAULT_CONFIG,

  async check(context: SecurityContext, config: RateLimitConfig) {
    try {
      const moduleId = JSON.stringify(config);
      let store = moduleStores.get(moduleId);
      if (!store) {
        store = await createStore(config);
        moduleStores.set(moduleId, store);
      }

      if (config.skipFunction && (await config.skipFunction(context))) {
        return { passed: true };
      }

      let identifier: string;
      if (config.keyGenerator) {
        identifier = await config.keyGenerator(context);
      } else {
        identifier =
          extractIp(context.request, config.ipHeaders, config.useRemoteAddress) || 'unknown';
      }

      const path = context.request.url || '';
      let resource: string | undefined = undefined;

      if (config.resources) {
        for (const [resourceKey, resourceConfig] of Object.entries(config.resources)) {
          if (path.includes(resourceKey)) {
            resource = resourceKey;
            break;
          }
        }
      }

      let country: string | undefined = undefined;

      country = context.data.get('geo-block:country') as string;

      if (!country && config.countryLimits && config.geoProvider) {
        const geoProvider = await createGeoProvider(config);
        if (geoProvider) {
          country = (await geoProvider.lookupCountry(identifier)) as string;
          if (country) {
            context.data.set('rate-limit:country', country);
          }
        }
      }

      const key = `${identifier}${resource ? `:${resource}` : ''}${country ? `:${country}` : ''}`;
      let effectiveConfig = { ...config };

      if (resource && config.resources && config.resources[resource]) {
        effectiveConfig.limit = config.resources[resource].limit;
        effectiveConfig.windowMs = config.resources[resource].windowMs;
      }

      if (country && config.countryLimits && config.countryLimits[country]) {
        effectiveConfig.limit = config.countryLimits[country].limit;
        effectiveConfig.windowMs = config.countryLimits[country].windowMs;
      }

      context.data.set('rate-limit:config', effectiveConfig);
      if (config.ddosPrevention?.enabled) {
        if (
          config.ddosPrevention.requestRateThreshold === 0 &&
          config.ddosPrevention.burstThreshold === 0
        ) {
          const threatData = {
            isThreat: true,
            level: 'medium' as const,
            score: 0.5,
            banDuration: config.ddosPrevention.banDurationMs,
          };

          context.data.set('rate-limit:ddos', threatData);

          return {
            passed: false,
            event: {
              type: RateLimitEventType.DDOS_PROTECTION_TRIGGERED,
              data: threatData,
              severity: 'medium',
            },
            reason: RateLimitEventType.DDOS_PROTECTION_TRIGGERED,
            data: threatData,
            severity: 'medium',
          };
        }

        const ddosProtection = new DDoSProtection(config);
        const threatAnalysis = await ddosProtection.analyze(key, context, store);

        if (threatAnalysis.isThreat) {
          context.data.set('rate-limit:ddos', threatAnalysis);

          return {
            passed: false,
            event: {
              type: RateLimitEventType.DDOS_PROTECTION_TRIGGERED,
              data: threatAnalysis,
              severity: threatAnalysis.level === 'critical' ? 'high' : 'medium',
            },
            reason: RateLimitEventType.DDOS_PROTECTION_TRIGGERED,
            data: threatAnalysis,
            severity: threatAnalysis.level === 'critical' ? 'high' : 'medium',
          };
        }
      }

      const strategy = createStrategy(effectiveConfig);
      const result = await strategy.check(key, context, effectiveConfig, store);
      context.data.set('rate-limit:result', result);

      if (config.headers && result) {
        addRateLimitHeaders(context, result, config);
      }

      if (!result.passed) {
        return {
          passed: false,
          event: {
            type: result.reason || RateLimitEventType.RATE_LIMITED,
            data: result.data,
            severity: 'low',
          },
          reason: result.reason || RateLimitEventType.RATE_LIMITED,
          data: result.data,
          severity: 'low',
        };
      }

      return { passed: true };
    } catch (error) {
      console.error('Error in rate-limit module:', error);
      return { passed: true };
    }
  },

  async handleFailure(context, reason, data) {
    const config = context.data.get('rate-limit:config') as RateLimitConfig;
    const result = context.data.get('rate-limit:result') as RateLimitResult;

    const res = context.response;
    if (res.headersSent || res.writableEnded) {
      return;
    }
    if (config.headers && result) {
      addRateLimitHeaders(context, result, config);
    }
    if (config.handler) {
      return config.handler(context, { reason, data });
    }
    const statusCode = config.statusCode || 429;
    let message = config.message || 'Too many requests, please try again later.';

    if (reason === RateLimitEventType.DDOS_PROTECTION_TRIGGERED) {
      message = 'Access temporarily blocked due to suspicious traffic patterns.';
    }
    if (result && result.retry) {
      res.setHeader('Retry-After', Math.ceil(result.retry / 1000).toString());
    }

    if (typeof res.status === 'function') {
      return res.status(statusCode).json({
        error: message,
        retryAfter: result && result.retry ? Math.ceil(result.retry / 1000) : undefined,
      });
    } else if (typeof res.statusCode === 'number') {
      res.statusCode = statusCode;
      res.setHeader('Content-Type', 'application/json');
      return res.end(
        JSON.stringify({
          error: message,
          retryAfter: result && result.retry ? Math.ceil(result.retry / 1000) : undefined,
        })
      );
    }
  },
});

registerModule('rateLimit', rateLimit);

export * from './types';
export * from './storage';
export * from './strategies/factory';
export * from './strategies';
