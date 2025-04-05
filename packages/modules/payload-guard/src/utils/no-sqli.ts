import { PATTERNS } from '../patterns';
import { PayloadCheckResult, PayloadGuardEventType } from '../types';

export function detectNoSQLi(value: string): PayloadCheckResult {
  if (typeof value !== 'string') return { detected: false };

  for (const pattern of PATTERNS.nosql) {
    if (pattern.test(value)) {
      return {
        detected: true,
        type: PayloadGuardEventType.GENERAL_INJECTION_DETECTED,
        value,
        pattern,
      };
    }
  }

  return { detected: false };
}
