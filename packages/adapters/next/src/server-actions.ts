import { SecurityModule, composeModules, createContext } from '@lock-sdk/core';
import { ServerActionFn, ServerActionSecuredFn } from './types';
import { createErrorData } from './utils';

/**
 * Creates a secured Server Action
 *
 * @param action The original Server Action function
 * @returns A function that takes security modules and returns a secured function
 */
export function secureServerAction<T extends ServerActionFn>(action: T): ServerActionSecuredFn<T> {
  return (...modules: SecurityModule[]): T => {
    const composedModule = composeModules(...modules);

    return (async (...args: Parameters<T>) => {
      const req: Record<string, any> = {
        headers: {} as Record<string, string>,
        cookies: {} as Record<string, string>,
        method: 'POST',
        url: '/',
        body: {},
      };

      const formDataArg = args.find(arg => arg instanceof FormData);
      if (formDataArg && formDataArg instanceof FormData) {
        const requestHeaders = formDataArg.get('$REQUEST_HEADERS');
        if (requestHeaders && typeof requestHeaders === 'string') {
          try {
            req.headers = JSON.parse(requestHeaders);
          } catch (e) {
            console.warn('Failed to parse request headers in server action');
          }
        }

        const csrfToken = formDataArg.get('csrf-token') || formDataArg.get('csrfToken');
        if (csrfToken && typeof csrfToken === 'string') {
          req.headers['x-csrf-token'] = csrfToken;
        }
      }

      const res: Record<string, any> = {
        headersSent: false,
        writableEnded: false,
        statusCode: 200,
        headers: {},
        status(code: number) {
          this.statusCode = code;
          return this;
        },
        setHeader(name: string, value: string) {
          this.headers[name] = value;
          return this;
        },
        json(body: any) {
          return body;
        },
      };

      const context = createContext(req, res, {});

      try {
        const result = await composedModule.check(context);

        if (result.passed) {
          return action(...args);
        } else {
          const errorData = createErrorData(context, result);
          throw new Error(JSON.stringify(errorData));
        }
      } catch (error) {
        if (error instanceof Error && error.message.startsWith('{')) {
          throw error;
        }

        console.error('Security middleware error:', error);
        throw new Error(
          JSON.stringify({
            error: 'Internal security error',
            statusCode: 500,
          })
        );
      }
    }) as T;
  };
}
