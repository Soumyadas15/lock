import {
  SecurityModule,
  SecurityContext,
  SecurityEvent,
  SecurityEventType,
  SecurityCheckResult,
} from './types';

/**
 * Core security manager responsible for running security modules.
 */
export class SecurityManager {
  private modules: SecurityModule[] = [];

  /**
   * Registers a security module.
   *
   * @param {SecurityModule} module - The security module to register.
   * @returns {this} The SecurityManager instance.
   */
  public registerModule(module: SecurityModule): this {
    this.modules.push(module);
    return this;
  }

  /**
   * Runs all registered security checks using the provided context.
   *
   * @param {SecurityContext} context - The initial security context.
   * @returns {Promise<boolean>} A promise that resolves to true if all checks pass; otherwise, false.
   */
  public async runSecurityChecks(context: SecurityContext): Promise<boolean> {
    try {
      for (const module of this.modules) {
        try {
          const result = await module.check(context);

          if (result.event) {
            context.events.push(result.event);
          }

          if (!result.passed) {
            context.denied = true;
            context.deniedReason = result.event?.message || `Security check failed: ${module.name}`;

            if (module.handleFailure && result.event) {
              await module.handleFailure(context, result.event);
            }

            return false;
          }
        } catch (error) {
          const errorEvent: SecurityEvent = {
            type: SecurityEventType.INTERNAL_ERROR,
            timestamp: Date.now(),
            message: `Error in module ${module.name}: ${
              error instanceof Error ? error.message : String(error)
            }`,
            data: error,
            severity: 'high',
            moduleName: module.name,
          };

          context.events.push(errorEvent);
          context.denied = true;
          context.deniedReason = errorEvent.message;

          if (module.handleFailure) {
            try {
              await module.handleFailure(context, errorEvent);
            } catch (handlerError) {
              console.error('Error in failure handler:', handlerError);
            }
          }

          return false;
        }
      }

      context.endTime = Date.now();
      return true;
    } catch (error) {
      console.error('Unexpected error in security manager:', error);

      context.denied = true;
      context.deniedReason = `Unexpected error: ${
        error instanceof Error ? error.message : String(error)
      }`;
      context.events.push({
        type: SecurityEventType.INTERNAL_ERROR,
        timestamp: Date.now(),
        message: context.deniedReason,
        data: error,
        severity: 'critical',
        moduleName: 'security-manager',
      });

      return false;
    }
  }
}
