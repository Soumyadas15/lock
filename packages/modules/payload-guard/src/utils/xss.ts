import { PATTERNS } from '../patterns';
import { PayloadCheckResult, PayloadGuardEventType } from '../types';

export function detectXSS(value: string): PayloadCheckResult {
  if (typeof value !== 'string') return { detected: false };
  if (/<form\s+id=test>.*?<input\s+id=parentNode\s+name=innerText>/i.test(value)) {
    return {
      detected: true,
      type: PayloadGuardEventType.XSS_DETECTED,
      value,
      pattern: /<form\s+id=test>.*?<input\s+id=parentNode\s+name=innerText>/i,
    };
  }

  for (const pattern of PATTERNS.xss) {
    if (pattern.test(value)) {
      return {
        detected: true,
        type: PayloadGuardEventType.XSS_DETECTED,
        value,
        pattern,
      };
    }
  }

  return { detected: false };
}
