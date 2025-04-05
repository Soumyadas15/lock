import { PATTERNS } from '../patterns';
import { PayloadCheckResult, PayloadGuardEventType } from '../types';

export function detectPathTraversal(value: string): PayloadCheckResult {
  if (typeof value !== 'string') return { detected: false };

  for (const pattern of PATTERNS.pathTraversal) {
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
