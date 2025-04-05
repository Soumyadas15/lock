import { SecurityModule, composeModules, createContext } from '@lock-sdk/core';
import { AppRouteHandler, AppRouteSecuredHandler } from './types';
import { createResponseProxy, createErrorResponse } from './utils';

/**
 * Creates a secured App Router API route handler
 *
 * @param handler The original App Router handler
 * @returns A function that takes security modules and returns a secured handler
 */
export function secureAppRoute<T = any>(handler: AppRouteHandler<T>): AppRouteSecuredHandler<T> {
  return (...modules: SecurityModule[]): AppRouteHandler<T> => {
    const composedModule = composeModules(...modules);

    return async req => {
      const resProxy = createResponseProxy();
      const context = createContext(req, resProxy, {});

      try {
        const result = await composedModule.check(context);

        if (result.passed) {
          const originalResponse = await handler(req);

          const responseClone = new Response(originalResponse.body, {
            status: originalResponse.status,
            statusText: originalResponse.statusText,
            headers: new Headers({
              ...Object.fromEntries(originalResponse.headers.entries()),
              ...Object.fromEntries(resProxy.headers.entries()),
            }),
          });

          return responseClone;
        } else {
          return createErrorResponse(context, result);
        }
      } catch (error) {
        console.error('Middleware error:', error);
        return new Response(JSON.stringify({ error: 'Internal security error' }), {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
          },
        });
      }
    };
  };
}
