import { GeoLocationProvider, RateLimitConfig } from '../types';
import { IpApiProvider } from './ipapi';

let globalGeoProvider: GeoLocationProvider | null = null;

export async function createGeoProvider(
  config: RateLimitConfig
): Promise<GeoLocationProvider | null> {
  if (globalGeoProvider) {
    return globalGeoProvider;
  }

  if (!config.geoProvider) {
    return null;
  }

  const providerType = config.geoProvider.type;

  switch (providerType) {
    case 'maxmind':
      if (!config.geoProvider.dbPath) {
        console.error('MaxMind DB path is required');
        return null;
      }

    case 'ipapi':
    default:
      globalGeoProvider = new IpApiProvider({
        cacheTtl: config.geoProvider.cacheTtl,
      });
      break;
  }

  return globalGeoProvider;
}
