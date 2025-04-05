import { PATTERNS } from '../patterns';
import { PayloadCheckResult, PayloadGuardEventType } from '../types';

export function detectCommandInjection(value: string): PayloadCheckResult {
  if (typeof value !== 'string') return { detected: false };

  for (const pattern of PATTERNS.commandInjection) {
    if (pattern.test(value)) {
      return {
        detected: true,
        type: PayloadGuardEventType.COMMAND_INJECTION_DETECTED,
        value,
        pattern,
      };
    }
  }

  return { detected: false };
}
