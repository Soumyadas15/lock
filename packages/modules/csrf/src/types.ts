export enum CSRFEventType {
  CSRF_TOKEN_MISSING = 'csrf.token.missing',
  CSRF_TOKEN_INVALID = 'csrf.token.invalid',
  CSRF_DOUBLE_SUBMIT_FAILURE = 'csrf.double.submit.failure',
  CSRF_VALIDATED = 'csrf.validated',
  CSRF_ERROR = 'csrf.error',
}

export type TokenLocation = 'cookie' | 'header' | 'cookie-header' | 'session';

export type TokenStorage = 'memory' | 'redis';

export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  path?: string;
  domain?: string;
  maxAge?: number;
}

export interface RedisOptions {
  host?: string;
  port?: number;
  password?: string;
  username?: string;
  db?: number;
  keyPrefix?: string;
  url?: string;
  client?: any;
}

export interface TokenStorageProvider {
  init(): Promise<void>;
  saveToken(token: string, identifier: string, ttl: number): Promise<void>;
  getToken(identifier: string): Promise<string | null>;
  validateToken(token: string, identifier: string): Promise<boolean>;
  deleteToken(identifier: string): Promise<void>;
  deleteExpiredTokens(): Promise<void>;
}

export interface CSRFConfig {
  enabled: boolean;
  tokenName: string;
  tokenLength: number;
  headerName: string;
  cookieName: string;
  cookieOptions: CookieOptions;
  storage: TokenStorage;
  tokenLocation: TokenLocation;
  ignoredMethods: string[];
  ignoredPaths: (string | RegExp)[];
  ignoredContentTypes: string[];
  failureStatusCode: number;
  failureMessage: string;
  refreshToken: boolean;
  tokenTtl: number;
  doubleSubmit: boolean;
  samesite: boolean;
  redisOptions?: RedisOptions;
  customStorage?: TokenStorageProvider;
  hashAlgorithm?: string;
  secret?: string;
  includeFormToken?: boolean;
  angularCompatible?: boolean;
}
