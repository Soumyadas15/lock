import { VPNDetectionConfig, VPNDetectionProviderInterface, VPNDetectionResult } from '../types';
import { IPAPIProvider } from './ipapi';
import { IPQualityScoreProvider } from './ipqualityscore';

export function createProvider(config: VPNDetectionConfig): VPNDetectionProviderInterface {
  switch (config.provider) {
    case 'ipqualityscore':
      return new IPQualityScoreProvider(config);
    case 'ipapi':
      return new IPAPIProvider(config);
    default:
      return new IPQualityScoreProvider(config);
  }
}

export * from './ipqualityscore';
export * from './ipapi';
