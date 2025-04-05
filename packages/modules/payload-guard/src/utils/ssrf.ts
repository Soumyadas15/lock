import { PayloadCheckResult, PayloadGuardEventType } from '../types';

export function detectSSRF(value: string): PayloadCheckResult {
  if (typeof value !== 'string') return { detected: false };

  if (
    value.includes('localhost') ||
    value.includes('127.0.0.1') ||
    value.match(/192\.168\.\d+\.\d+/) ||
    value.match(/10\.\d+\.\d+\.\d+/) ||
    value.match(/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/)
  ) {
    return {
      detected: true,
      type: PayloadGuardEventType.PATH_TRAVERSAL_DETECTED,
      value,
      pattern: /localhost|127\.0\.0\.1/,
    };
  }

  const ssrfPatterns = [
    /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
    /https?:\/\/(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)/i,
    /https?:\/\/(?:[^.]+\.)?(?:internal|corp|local|intranet|private)/i,
    /https?:\/\/[^\/]+(?:\.\/|\.\.\/|%2e\.\/|%2e%2e\/)/i,
    /^file:\/\//i,
  ];

  for (const pattern of ssrfPatterns) {
    if (pattern.test(value)) {
      return {
        detected: true,
        type: PayloadGuardEventType.PATH_TRAVERSAL_DETECTED,
        value,
        pattern,
      };
    }
  }

  return { detected: false };
}
