import { PayloadCheckResult } from '../types';

/**
 * Recursively traverses an object to check each string value for injection attacks
 * @param obj The object to check
 * @param path Current path in the object (for reporting)
 * @param detectors Array of detector functions to run
 * @param excludeFields Fields to exclude from checking
 */
export function traverseAndCheck(
  obj: any,
  path: string = '',
  detectors: Array<(value: string) => PayloadCheckResult>,
  excludeFields: string[] = []
): PayloadCheckResult {
  if (obj === null || obj === undefined) {
    return { detected: false };
  }

  if (typeof obj === 'string') {
    const isSafePlainText = (str: string): boolean => {
      const hasNoSuspiciousPatterns = !/[<>{}()|;$=\[\]`']/.test(str);

      const hasSQLKeywordsButNoSyntax =
        /\b(select|insert|update|delete|from|where)\b/i.test(str) &&
        !/['"]|--|#|\/\*|\b(union|join)\b/i.test(str);

      return hasNoSuspiciousPatterns || hasSQLKeywordsButNoSyntax;
    };

    if (isSafePlainText(obj)) {
      return { detected: false };
    }
    for (const detector of detectors) {
      const result = detector(obj);
      if (result.detected) {
        result.path = path;
        return result;
      }
    }
    return { detected: false };
  }

  if (typeof obj !== 'object') {
    return { detected: false };
  }

  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      const result = traverseAndCheck(
        obj[i],
        path ? `${path}[${i}]` : `[${i}]`,
        detectors,
        excludeFields
      );
      if (result.detected) {
        return result;
      }
    }
    return { detected: false };
  }

  for (const key in obj) {
    if (excludeFields.includes(key)) {
      continue;
    }

    const newPath = path ? `${path}.${key}` : key;
    const result = traverseAndCheck(obj[key], newPath, detectors, excludeFields);

    if (result.detected) {
      return result;
    }
  }

  return { detected: false };
}
