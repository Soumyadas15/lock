import { SecurityContext, SecurityCheckResult } from '@lock-sdk/core';
import { ResponseProxy, SecurityErrorMetadata, SecurityErrorResponse } from '../types';

/**
 * Creates a response proxy object that simulates a response for App Router and Edge
 * @returns A response proxy object
 */
export function createResponseProxy(): ResponseProxy {
  return {
    headersSent: false,
    writableEnded: false,
    statusCode: 200,
    headers: new Headers(),
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    setHeader(name: string, value: string) {
      this.headers.set(name, value);
      return this;
    },
    json(body: any) {
      return new Response(JSON.stringify(body), {
        status: this.statusCode,
        headers: this.headers,
      });
    },
  };
}

/**
 * Extracts metadata from a security check result
 * @param context The security context
 * @param result The security check result
 * @returns Metadata about the security event
 */
export function extractSecurityMetadata(result: SecurityCheckResult): SecurityErrorMetadata {
  if (result.event) {
    return {
      module: result.event.moduleName,
      reason: result.event.message,
      type: result.event.type,
      timestamp: new Date(result.event.timestamp).toISOString(),
      severity: result.event.severity,
      details: result.event.data || {},
    };
  } else {
    return {
      module: 'unknown',
      reason: 'Access denied by security policy',
      timestamp: new Date().toISOString(),
      details: {},
    };
  }
}

/**
 * Gets custom configuration for error responses from a module
 * @param context The security context
 * @param result The security check result
 * @returns Custom error configuration
 */
export function getErrorConfig(
  context: SecurityContext,
  result: SecurityCheckResult
): { statusCode: number; errorMessage: string } {
  let statusCode = 403;
  let errorMessage = 'Access denied by security policy';

  if (result.event && result.event.moduleName) {
    const configKey = `${result.event.moduleName}:config`;
    const config = context.data.get(configKey);

    if (config) {
      statusCode = config.blockStatusCode || config.statusCode || statusCode;
      errorMessage = config.blockMessage || config.message || errorMessage;
    }
  }

  return { statusCode, errorMessage };
}

/**
 * Creates an error response object for security failures
 * @param context The security context
 * @param result The security check result
 * @returns An error response data object
 */
export function createErrorData(
  context: SecurityContext,
  result: SecurityCheckResult
): SecurityErrorResponse {
  const metadata = extractSecurityMetadata(result);
  const { statusCode, errorMessage } = getErrorConfig(context, result);

  return {
    error: errorMessage,
    blocked: true,
    meta: metadata,
    statusCode,
  };
}

/**
 * Creates a Response object for security failures
 * @param context The security context
 * @param result The security check result
 * @returns A Response object
 */
export function createErrorResponse(
  context: SecurityContext,
  result: SecurityCheckResult
): Response {
  const errorData = createErrorData(context, result);

  // Get headers from the response proxy if available
  const headers = new Headers({
    'Content-Type': 'application/json',
  });

  // Add any headers that were set during the security check
  if (context.response && 'headers' in context.response) {
    const responseHeaders = context.response.headers;
    if (responseHeaders instanceof Headers) {
      // Copy all headers from the response proxy
      responseHeaders.forEach((value, key) => {
        headers.set(key, value);
      });
    } else if (typeof responseHeaders === 'object') {
      // Handle plain object headers
      Object.entries(responseHeaders).forEach(([key, value]) => {
        if (typeof value === 'string') {
          headers.set(key, value);
        }
      });
    }
  }

  return new Response(JSON.stringify(errorData), {
    status: errorData.statusCode,
    headers,
  });
}

/**
 * Handles security failure for Pages API routes
 * @param context The security context
 * @param result The security check result
 * @param res The NextApiResponse object
 */
export function handleSecurityFailure(
  context: SecurityContext,
  result: SecurityCheckResult,
  res: any
): void {
  if (!res.headersSent && !res.writableEnded) {
    const errorData = createErrorData(context, result);
    res.status(errorData.statusCode).json({
      error: errorData.error,
      blocked: true,
      meta: errorData.meta,
    });
  }
}
