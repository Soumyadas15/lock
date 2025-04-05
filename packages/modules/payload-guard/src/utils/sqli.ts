import { PATTERNS } from '../patterns';
import { PayloadCheckResult, PayloadGuardEventType } from '../types';

export function detectSQLi(value: string): PayloadCheckResult {
  if (typeof value !== 'string') return { detected: false };

  for (const pattern of PATTERNS.sqli) {
    if (pattern.test(value)) {
      return {
        detected: true,
        type: PayloadGuardEventType.SQL_INJECTION_DETECTED,
        value,
        pattern,
      };
    }
  }

  return { detected: false };
}
