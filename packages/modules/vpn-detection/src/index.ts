import { VPNDetectionConfig, VPNDetectionEventType, VPNDetectionResult } from './types';
import { createModule, SecurityContext } from '@lock-sdk/core';
import { registerModule } from '@lock-sdk/core';
import { extractIp } from './utils/extract-ip';
import { createProvider } from './providers';
import { createCacheStore, VPNCacheStore } from './storage';

const DEFAULT_CONFIG: Partial<VPNDetectionConfig> = {
  ipHeaders: ['cf-connecting-ip', 'x-forwarded-for', 'x-real-ip'],
  useRemoteAddress: true,
  blockStatusCode: 403,
  blockMessage: 'Access denied: VPN or proxy detected',
  provider: 'ipapi',
  storage: 'memory',
  cacheTtl: 3600000,
  cacheSize: 10000,
  vpnScoreThreshold: 0.7,
  proxyScoreThreshold: 0.7,
  datacenterScoreThreshold: 0.7,
  torScoreThreshold: 0.7,
  checkVpn: true,
  checkProxy: true,
  checkDatacenter: true,
  checkTor: true,
  failBehavior: 'open',
  blockTor: true,
  blockVpn: true,
  blockProxy: true,
  blockDatacenter: false,
  customProviderOptions: {},
};

let vpnCache: VPNCacheStore | null = null;
let provider: any = null;

export const vpnDetector = createModule<VPNDetectionConfig>({
  name: 'vpn-detector',

  defaultConfig: DEFAULT_CONFIG,

  async check(context: SecurityContext, config: VPNDetectionConfig) {
    try {
      if (!vpnCache) {
        try {
          vpnCache = await createCacheStore(config);
        } catch (cacheError) {
          console.error(`Failed to initialize VPN cache: ${(cacheError as Error).message}`);
          const { MemoryVPNCacheStore } = await import('./storage');
          vpnCache = new MemoryVPNCacheStore(config);
          await vpnCache.init();
        }
      }

      const ip = extractIp(context.request, config.ipHeaders, config.useRemoteAddress);
      if (!ip) {
        console.warn('No IP address could be extracted from the request');

        return {
          passed: config.failBehavior === 'open',
          reason:
            config.failBehavior === 'closed'
              ? VPNDetectionEventType.VPN_DETECTION_ERROR
              : undefined,
          data: { error: 'Could not determine client IP address' },
          severity: 'medium',
        };
      }

      try {
        let detectionResult = await vpnCache.get(ip);

        if (!detectionResult) {
          if (!provider) {
            provider = createProvider(config);
            try {
              await provider.init();
            } catch (initError) {
              console.error(
                `Failed to initialize VPN detection provider: ${(initError as Error).message}`
              );

              if (config.failBehavior === 'closed') {
                return {
                  passed: false,
                  reason: VPNDetectionEventType.VPN_DETECTION_ERROR,
                  data: { error: 'VPN detection provider failed to initialize' },
                  severity: 'medium',
                };
              }

              return { passed: true };
            }
          }

          detectionResult = await provider.checkIp(ip);

          if (detectionResult && Object.keys(detectionResult).length > 0) {
            await vpnCache.set(ip, detectionResult);
          }
        }

        if (!detectionResult) {
          console.warn(`No VPN detection information found for IP: ${ip}`);
          return { passed: true };
        }

        let isBlocked = false;
        let blockReason = '';

        if (
          config.checkVpn &&
          config.blockVpn &&
          detectionResult.isVpn &&
          config.vpnScoreThreshold &&
          detectionResult.vpnScore >= config.vpnScoreThreshold
        ) {
          isBlocked = true;
          blockReason = 'VPN detected';
        }

        if (
          config.checkProxy &&
          config.blockProxy &&
          config.proxyScoreThreshold &&
          detectionResult.isProxy &&
          detectionResult.proxyScore >= config.proxyScoreThreshold
        ) {
          isBlocked = true;
          blockReason = blockReason ? `${blockReason}, proxy detected` : 'Proxy detected';
        }

        if (
          config.checkTor &&
          config.blockTor &&
          config.torScoreThreshold &&
          detectionResult.isTor &&
          detectionResult.torScore >= config.torScoreThreshold
        ) {
          isBlocked = true;
          blockReason = blockReason ? `${blockReason}, Tor detected` : 'Tor detected';
        }

        if (
          config.checkDatacenter &&
          config.blockDatacenter &&
          config.datacenterScoreThreshold &&
          detectionResult.isDatacenter &&
          detectionResult.datacenterScore >= config.datacenterScoreThreshold
        ) {
          isBlocked = true;
          blockReason = blockReason
            ? `${blockReason}, datacenter IP detected`
            : 'Datacenter IP detected';
        }

        if (isBlocked) {
          return {
            passed: false,
            reason: VPNDetectionEventType.VPN_DETECTED,
            data: { ip, detectionResult, reason: blockReason },
            severity: 'medium',
          };
        }

        return {
          passed: true,
          reason: VPNDetectionEventType.NO_VPN_DETECTED,
          data: { ip, detectionResult },
          severity: 'low',
        };
      } catch (detectionError) {
        console.error(`Error during VPN detection for IP ${ip}:`, detectionError);
        if (config.failBehavior === 'closed') {
          return {
            passed: false,
            reason: VPNDetectionEventType.VPN_DETECTION_ERROR,
            data: { error: 'VPN detection failed', ip },
            severity: 'medium',
          };
        }
        return { passed: true };
      }
    } catch (error) {
      console.error(`Unexpected error in vpn-detector module:`, error);
      return {
        passed: config.failBehavior !== 'closed',
        reason:
          config.failBehavior === 'closed' ? VPNDetectionEventType.VPN_DETECTION_ERROR : undefined,
        data:
          config.failBehavior === 'closed' ? { error: 'VPN detection module failed' } : undefined,
        severity: 'medium',
      };
    }
  },

  async handleFailure(context, reason, data) {
    const config = context.data.get('vpn-detector:config') as VPNDetectionConfig;
    const res = context.response;
    if (res.headersSent || res.writableEnded) {
      return;
    }

    let message = config.blockMessage ?? 'Access denied: VPN or proxy detected';
    if (data?.reason) {
      message = `${message}: ${data.reason}`;
    }

    if (typeof res.status === 'function') {
      return res.status(config.blockStatusCode ?? 403).json({
        error: message,
        blocked: true,
        details: data?.detectionResult || {},
      });
    } else if (typeof res.statusCode === 'number') {
      res.statusCode = config.blockStatusCode ?? 403;
      res.setHeader('Content-Type', 'application/json');
      return res.end(
        JSON.stringify({
          error: message,
          blocked: true,
          details: data?.detectionResult || {},
        })
      );
    }
  },
});

registerModule('vpnDetector', vpnDetector);

export * from './types';
export * from './utils/extract-ip';
export * from './providers';
export * from './storage';
