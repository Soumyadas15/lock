import { createModule, SecurityContext, registerModule } from '@lock-sdk/core';
import { LRUCache } from 'lru-cache';
import { PayloadGuardConfig, PayloadGuardEventType, PayloadCheckResult } from './types';
import {
  detectXSS,
  detectSQLi,
  detectCommandInjection,
  detectPathTraversal,
  detectNoSQLi,
  detectTemplateInjection,
  traverseAndCheck,
  generateHash,
  detectSSRF,
} from './utils';

const DEFAULT_CONFIG: Partial<PayloadGuardConfig> = {
  mode: 'block',
  blockStatusCode: 403,
  blockMessage: 'Request blocked due to potential security threat',
  checkParts: ['params', 'query', 'body', 'headers'],
  excludeHeaders: ['authorization', 'cookie', 'set-cookie'],
  excludeFields: [],
  detectXSS: true,
  detectSSRF: true,
  detectSQLi: true,
  detectCommandInjection: true,
  detectPathTraversal: true,
  enableCaching: true,
  cacheTtl: 3600000,
  cacheSize: 10000,
  failBehavior: 'open',
};

export const payloadGuard = createModule<PayloadGuardConfig>({
  name: 'payload-guard',

  defaultConfig: DEFAULT_CONFIG,

  async check(context: SecurityContext, config: PayloadGuardConfig) {
    try {
      if (!context.request) {
        console.error('PayloadGuard: Request object is null or undefined');
        return {
          passed: config.failBehavior !== 'closed',
          reason:
            config.failBehavior === 'closed'
              ? PayloadGuardEventType.GENERAL_INJECTION_DETECTED
              : undefined,
          data:
            config.failBehavior === 'closed'
              ? { error: 'PayloadGuard module failed - request is null' }
              : undefined,
          severity: 'medium',
        };
      }

      const cache = config.enableCaching
        ? new LRUCache<string, PayloadCheckResult>({
            max: config.cacheSize!,
            ttl: config.cacheTtl,
            ttlAutopurge: true,
          })
        : null;

      const detectors: Array<(value: string) => PayloadCheckResult> = [];

      if (config.detectXSS) {
        detectors.push(detectXSS);
      }

      if (config.detectSQLi) {
        detectors.push(detectSQLi);
      }

      if (config.detectSSRF) {
        detectors.push(detectSSRF);
      }

      if (config.detectCommandInjection) {
        detectors.push(detectCommandInjection);
      }

      if (config.detectPathTraversal) {
        detectors.push(detectPathTraversal);
      }

      detectors.push(detectNoSQLi);
      detectors.push(detectTemplateInjection);
      if (detectors.length === 0) {
        return { passed: true };
      }

      const checkParts = config.checkParts || ['params', 'query', 'body', 'headers'];
      const excludeHeaders = (config.excludeHeaders || []).map(h => h.toLowerCase());

      const req = context.request;

      for (const part of checkParts) {
        // Skip if the part doesn't exist in request
        if (!req[part]) continue;

        if (part === 'headers') {
          const headers = { ...req.headers };

          for (const header of excludeHeaders) {
            delete headers[header];
          }
          const result = traverseAndCheck(
            headers,
            'headers',
            detectors,
            config.excludeFields || []
          );

          if (result.detected) {
            return {
              passed: config.mode === 'detect',
              reason: result.type,
              data: {
                path: result.path,
                value: result.value,
                pattern: result.pattern?.toString(),
              },
              severity: 'high',
            };
          }
        } else {
          let result: PayloadCheckResult;

          if (cache) {
            const reqPartStr = JSON.stringify(req[part]);
            const hash = generateHash(reqPartStr);

            const cachedResult = cache.get(hash);

            if (cachedResult) {
              result = cachedResult;
            } else {
              result = traverseAndCheck(req[part], part, detectors, config.excludeFields || []);
              cache.set(hash, result);
            }
          } else {
            result = traverseAndCheck(req[part], part, detectors, config.excludeFields || []);
          }

          if (result.detected) {
            return {
              passed: config.mode === 'detect',
              reason: result.type,
              data: {
                path: result.path,
                value: result.value,
                pattern: result.pattern?.toString(),
              },
              severity: 'high',
            };
          }
        }
      }

      return { passed: true };
    } catch (error) {
      console.error(`Unexpected error in PayloadGuard module:`, error);
      return {
        passed: config.failBehavior !== 'closed',
        reason:
          config.failBehavior === 'closed'
            ? PayloadGuardEventType.GENERAL_INJECTION_DETECTED
            : undefined,
        data:
          config.failBehavior === 'closed' ? { error: 'PayloadGuard module failed' } : undefined,
        severity: 'medium',
      };
    }
  },

  async handleFailure(context, reason, data) {
    const config = context.data.get('payload-guard:config') as PayloadGuardConfig;
    const res = context.response;

    if (res.headersSent || res.writableEnded) {
      return;
    }

    const message = config.blockMessage || 'Request blocked due to potential security threat';
    const statusCode = config.blockStatusCode || 403;

    if (typeof res.status === 'function') {
      return res.status(statusCode).json({
        error: message,
        details: {
          reason,
          ...data,
        },
      });
    } else if (typeof res.statusCode === 'number') {
      res.statusCode = statusCode;
      res.setHeader('Content-Type', 'application/json');
      return res.end(
        JSON.stringify({
          error: message,
          details: {
            reason,
            ...data,
          },
        })
      );
    }
  },
});

registerModule('payloadGuard', payloadGuard);

export * from './types';
export * from './utils';
export * from './patterns';
