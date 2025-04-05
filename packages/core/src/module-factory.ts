import {
  SecurityModule,
  SecurityContext,
  SecurityEvent,
  SecurityEventType,
  SecurityCheckResult,
} from './types';

/**
 * Definition for creating a security module.
 *
 * @template TConfig - The type of the configuration object.
 */
export interface ModuleDefinition<TConfig = any> {
  /**
   * Module name.
   */
  name: string;

  /**
   * Module check function.
   *
   * @param {SecurityContext} context - The security context.
   * @param {TConfig} config - The module configuration.
   * @returns {Promise<{ passed: boolean; reason?: string; data?: any; severity?: 'low' | 'medium' | 'high' | 'critical' }>}
   * A promise that resolves to an object indicating whether the check passed, along with optional reason, data, and severity.
   */
  check: (
    context: SecurityContext,
    config: TConfig
  ) => Promise<{
    passed: boolean;
    reason?: string;
    data?: any;
    severity?: 'low' | 'medium' | 'high' | 'critical';
  }>;

  /**
   * Optional failure handler.
   *
   * @param {SecurityContext} context - The security context.
   * @param {string} reason - The reason for failure.
   * @param {*} [data] - Optional additional data.
   * @returns {Promise<void>} A promise that resolves when the failure is handled.
   */
  handleFailure?: (context: SecurityContext, reason: string, data?: any) => Promise<void>;

  /**
   * Default configuration for the module.
   */
  defaultConfig?: Partial<TConfig>;
}

/**
 * Creates a security module factory.
 *
 * @param definition Module definition.
 * @returns Factory function that creates configured security modules.
 */
export function createModule<TConfig = any>(
  definition: ModuleDefinition<TConfig>
): (config?: Partial<TConfig>) => SecurityModule {
  return (config?: Partial<TConfig>) => {
    const mergedConfig = {
      ...definition.defaultConfig,
      ...config,
    } as TConfig;

    return {
      name: definition.name,

      async check(context: SecurityContext): Promise<SecurityCheckResult> {
        try {
          context.data.set(`${definition.name}:config`, mergedConfig);
          const result = await definition.check(context, mergedConfig);
          if (!result.passed) {
            const event: SecurityEvent = {
              type: (result.reason as any) || SecurityEventType.INTERNAL_ERROR,
              timestamp: Date.now(),
              message: result.reason || 'Security check failed',
              data: result.data,
              severity: result.severity || 'medium',
              moduleName: definition.name,
            };
            return {
              passed: false,
              event,
              context,
            };
          }
          return { passed: true, context };
        } catch (error) {
          const event: SecurityEvent = {
            type: SecurityEventType.INTERNAL_ERROR,
            timestamp: Date.now(),
            message: `Error in ${definition.name}: ${error instanceof Error ? error.message : String(error)}`,
            data: error,
            severity: 'high',
            moduleName: definition.name,
          };
          return {
            passed: false,
            event,
            context,
          };
        }
      },

      async handleFailure(context: SecurityContext, event: SecurityEvent): Promise<void> {
        if (definition.handleFailure) {
          await definition.handleFailure(context, event.message, event.data);
        }
      },
    };
  };
}
