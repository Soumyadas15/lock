export enum PayloadGuardEventType {
  XSS_DETECTED = 'xss.detected',
  SQL_INJECTION_DETECTED = 'sql.injection.detected',
  COMMAND_INJECTION_DETECTED = 'command.injection.detected',
  PATH_TRAVERSAL_DETECTED = 'path.traversal.detected',
  GENERAL_INJECTION_DETECTED = 'general.injection.detected',
  SSRF_DETECTED = 'ssrf.detected',
}

export interface PayloadGuardConfig {
  mode: 'detect' | 'block';
  blockStatusCode?: number;
  blockMessage?: string;
  checkParts?: Array<'params' | 'query' | 'body' | 'headers' | 'cookies'>;
  excludeHeaders?: string[];
  excludeFields?: string[];
  detectXSS?: boolean;
  detectSSRF?: boolean;
  detectSQLi?: boolean;
  detectCommandInjection?: boolean;
  detectPathTraversal?: boolean;
  enableCaching?: boolean;
  cacheTtl?: number;
  cacheSize?: number;
  failBehavior?: 'open' | 'closed';
}

export interface PayloadCheckResult {
  detected: boolean;
  type?: PayloadGuardEventType;
  path?: string;
  value?: string;
  pattern?: RegExp;
}
