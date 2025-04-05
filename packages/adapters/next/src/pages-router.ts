import { SecurityModule, composeModules, createContext } from '@lock-sdk/core';
import { NextApiHandler, NextApiSecuredHandler } from './types';
import { handleSecurityFailure } from './utils';

/**
 * Creates a secured Pages API route handler
 *
 * @param handler The original Next.js API route handler
 * @returns A function that takes security modules and returns a secured handler
 */
export function securePageRoute<T = any>(handler: NextApiHandler<T>): NextApiSecuredHandler<T> {
  return (...modules: SecurityModule[]): NextApiHandler<T> => {
    const composedModule = composeModules(...modules);

    return async (req, res) => {
      const context = createContext(req, res, {});

      try {
        const result = await composedModule.check(context);

        if (result.passed) {
          return handler(req, res);
        } else {
          handleSecurityFailure(context, result, res);
        }
      } catch (error) {
        console.error('Security middleware error:', error);
        if (!res.headersSent) {
          return res.status(500).json({ error: 'Internal security error' } as any);
        }
      }
    };
  };
}
