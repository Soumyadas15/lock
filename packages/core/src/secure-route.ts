import { SecurityModule, composeModules, createContext } from './index';

const moduleRegistry: Record<string, (config: any) => SecurityModule> = {};

/**
 * Register a security module for use with secureRoute
 * @param name Module name to use in configuration
 * @param factory Module factory function
 */
export function registerModule(name: string, factory: (config: any) => SecurityModule) {
  moduleRegistry[name] = factory;
  return factory;
}

/**
 * Secure route handler with declarative configuration.
 *
 * Wraps an original route handler (Next.js, Express, etc.) with security checks using configured modules.
 * If no modules are configured, the original handler is returned. Otherwise, the security checks are performed
 * using the composed security modules, and access is allowed only if all checks pass.
 *
 * @param {Function} handler - The original route handler.
 * @param {Record<string, any>} [options={}] - Security configuration options.
 * @returns {Function} The secured route handler.
 */
export function secureRoute(handler: Function, options: Record<string, any> = {}) {
  const modules: SecurityModule[] = [];

  for (const [key, config] of Object.entries(options)) {
    if (moduleRegistry[key]) {
      modules.push(moduleRegistry[key](config));
    } else {
      console.warn(
        `Unknown security module: ${key}. Make sure it's registered with registerModule().`
      );
    }
  }

  if (modules.length === 0) {
    return handler;
  }

  const composedModule = composeModules(...modules);

  return async function securedHandler(req: any, res: any, next?: Function) {
    const context = createContext(req, res, {});

    try {
      const result = await composedModule.check(context);

      if (result.passed) {
        if (typeof next === 'function') {
          return next();
        }
        return handler(req, res);
      } else {
        if (!res.headersSent && !res.writableEnded) {
          const moduleInfo = result.event
            ? {
                module: result.event.moduleName,
                reason: result.event.message,
                type: result.event.type,
                timestamp: new Date(result.event.timestamp).toISOString(),
                severity: result.event.severity,
                details: result.event.data || {},
              }
            : {
                module: 'unknown',
                reason: 'Access denied by security policy',
              };

          res.status(403).json({
            error: 'Access denied by security policy',
            blocked: true,
            meta: moduleInfo,
          });
        }
      }
    } catch (error) {
      console.error('Error in security middleware:', error);

      if (res && !context.response.headersSent) {
        if (typeof res.status === 'function') {
          res.status(500).json({ error: 'Internal security error' });
        } else if (typeof res.statusCode === 'number') {
          res.statusCode = 500;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ error: 'Internal security error' }));
        }
      }
    }
  };
}

/**
 * Secures a route handler or middleware by applying security modules.
 * The returned function accepts security modules and returns an asynchronous middleware.
 * If the security checks pass, it calls the original handler (Next.js style) or next middleware (Express style).
 * Otherwise, it sends a 403 response with detailed metadata about the security event.
 *
 * @param {Function} [handler] - Optional original route handler.
 * @returns {(...modules: SecurityModule[]) => Function} A function that takes security modules and returns a secured middleware.
 */
export function secure(handler?: Function) {
  return (...modules: SecurityModule[]) => {
    const composedModule = composeModules(...modules);
    return async (req: any, res: any, next?: Function) => {
      const context = createContext(req, res, {});
      try {
        const result = await composedModule.check(context);
        if (result.passed) {
          if (handler) {
            return handler(req, res);
          } else if (typeof next === 'function') {
            return next();
          }
        } else {
          if (!res.headersSent && !res.writableEnded) {
            const moduleInfo = result.event
              ? {
                  module: result.event.moduleName,
                  reason: result.event.message,
                  type: result.event.type,
                  timestamp: new Date(result.event.timestamp).toISOString(),
                  severity: result.event.severity,
                  details: result.event.data || {},
                }
              : {
                  module: 'unknown',
                  reason: 'Access denied by security policy',
                };

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
            res.status(statusCode).json({
              error: errorMessage,
              blocked: true,
              meta: moduleInfo,
            });
          }
        }
      } catch (error) {
        console.error('Security error:', error);
        if (!res.headersSent && !res.writableEnded) {
          res.status(500).json({ error: 'Internal security error' });
        }
      }
    };
  };
}
