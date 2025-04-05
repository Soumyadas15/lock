import { PATTERNS } from '../patterns';
import { PayloadCheckResult, PayloadGuardEventType } from '../types';

export function detectTemplateInjection(value: string): PayloadCheckResult {
  if (typeof value !== 'string') return { detected: false };

  for (const pattern of PATTERNS.templateInjection) {
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
