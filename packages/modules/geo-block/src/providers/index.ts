import * as fs from 'fs';
import { GeoLookupProvider, GeoBlockConfig } from '../types';
import { MaxMindProvider } from './maxmind';
import { IpApiProvider } from './ip-api';

export function createProvider(config: GeoBlockConfig): GeoLookupProvider {
  if (config.provider === 'maxmind') {
    if (!config.maxmindDbPath || !fs.existsSync(config.maxmindDbPath)) {
      console.warn(
        `MaxMind database not found at path: ${config.maxmindDbPath || 'undefined'}. ` +
          `Falling back to ip-api.com service.`
      );
      return new IpApiProvider(config);
    }
    return new MaxMindProvider(config);
  }
  switch (config.provider) {
    case 'ipapi':
      return new IpApiProvider(config);
    default:
      console.warn(`Unknown provider: ${config.provider}. Falling back to ip-api.com service.`);
      return new IpApiProvider(config);
  }
}
