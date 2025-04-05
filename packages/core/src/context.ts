import { SecurityContext } from './types';

/**
 * Creates a new security context.
 *
 * @template TRequest The type of the request.
 * @template TResponse The type of the response.
 * @param {TRequest} request - The request object.
 * @param {TResponse} response - The response object.
 * @param {Record<string, any>} [config={}] - Optional configuration object.
 * @returns {SecurityContext<TRequest, TResponse>} A new security context object.
 */
export function createContext<TRequest, TResponse>(
  request: TRequest,
  response: TResponse,
  config: Record<string, any> = {}
): SecurityContext<TRequest, TResponse> {
  return {
    request,
    response,
    denied: false,
    events: [],
    startTime: Date.now(),
    data: new Map(),
    config,
  };
}
