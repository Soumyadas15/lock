import { SecurityModule } from './types';

/**
 * Creates a security pipeline by composing multiple security modules.
 * The returned module performs a sequential check using the provided modules.
 * If any module fails its check, the pipeline stops and returns that failure result.
 * Additionally, it delegates failure handling to the specific module that failed.
 *
 * @param {...SecurityModule[]} modules - An array of security modules to be composed.
 * @returns {SecurityModule} A composed security module that integrates the provided modules.
 */
export function composeModules(...modules: SecurityModule[]): SecurityModule {
  return {
    name: 'composed-modules',

    async check(context) {
      for (const module of modules) {
        const result = await module.check(context);
        if (!result.passed) {
          return result;
        }
      }
      return { passed: true, context };
    },

    async handleFailure(context, event) {
      const module = modules.find(m => m.name === event.moduleName);
      if (module && module.handleFailure) {
        await module.handleFailure(context, event);
      }
    },
  };
}
