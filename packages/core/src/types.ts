/**
 * Security context that's passed through the module chain
 */
export interface SecurityContext<TRequest = any, TResponse = any> {
  /** Original request object (framework-specific) */
  request: TRequest;

  /** Original response object (framework-specific) */
  response: TResponse;

  /** Authenticated user object (if available) */
  user?: any;

  /** Whether the request has been denied by any security module */
  denied: boolean;

  /** Reason for denial (if denied) */
  deniedReason?: string;

  /** Security events that occurred during processing */
  events: SecurityEvent[];

  /** Timestamp when processing started */
  startTime: number;

  /** Timestamp when processing ended */
  endTime?: number;

  /** Custom data shared between modules */
  data: Map<string, any>;

  /** Security configuration */
  config: Record<string, any>;
}

/**
 * Severity level for security events
 */
export type SecurityEventSeverity = 'low' | 'medium' | 'high' | 'critical';

/**
 * Security event types
 */
export enum SecurityEventType {
  /** Authentication successful */
  AUTH_SUCCESS = 'auth_success',

  /** Authentication failed */
  AUTH_FAILURE = 'auth_failure',

  /** Rate limit exceeded */
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',

  /** Input validation failed */
  VALIDATION_FAILURE = 'validation_failure',

  /** CSRF token invalid/missing */
  CSRF_VIOLATION = 'csrf_violation',

  /** Access denied due to insufficient permissions */
  AUTHORIZATION_FAILURE = 'authorization_failure',

  /** Access denied due to geographic restrictions */
  GEO_BLOCKED = 'geo_blocked',

  /** Internal error occurred */
  INTERNAL_ERROR = 'internal_error',
}

/**
 * Security event details
 */
export interface SecurityEvent {
  /** Type of event */
  type: SecurityEventType;

  /** Timestamp when event occurred */
  timestamp: number;

  /** Human-readable message */
  message: string;

  /** Additional event data */
  data?: any;

  /** Event severity */
  severity: SecurityEventSeverity;

  /** Module that generated the event */
  moduleName: string;
}

/**
 * Result of a security check
 */
export interface SecurityCheckResult {
  /** Whether the check passed */
  passed: boolean;

  /** Event details if the check failed */
  event?: SecurityEvent;

  /** Updated security context */
  context: SecurityContext;
}

/**
 * Base security module interface
 */
export interface SecurityModule {
  /** Unique module name */
  name: string;

  /**
   * Run security check
   * @param context Current security context
   * @returns Result of the security check
   */
  check(context: SecurityContext): Promise<SecurityCheckResult>;

  /**
   * Handle failure if the check fails
   * @param context Current security context
   * @param event Security event that caused the failure
   */
  handleFailure?(context: SecurityContext, event: SecurityEvent): Promise<void>;
}
