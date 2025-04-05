import type { NextApiRequest, NextApiResponse } from 'next';
import type { NextRequest } from 'next/server';
import { SecurityModule } from '@lock-sdk/core';

// Pages Router types
export type NextApiHandler<T = any> = (
  req: NextApiRequest,
  res: NextApiResponse<T>
) => Promise<void> | void;

export type NextApiSecuredHandler<T = any> = (...modules: SecurityModule[]) => NextApiHandler<T>;

// App Router types
export type NextResponseData = any;
export type NextResponseInit = ResponseInit & { url?: string };

// Minimal Next.js Response type
export interface NextResponse<T = NextResponseData> extends Response {
  readonly headers: Headers;
  readonly ok: boolean;
  readonly redirected: boolean;
  readonly status: number;
  readonly statusText: string;
  readonly type: ResponseType;
  readonly url: string;
  readonly body: ReadableStream<Uint8Array> | null;
  readonly bodyUsed: boolean;
  clone(): NextResponse<T>;
  json(): Promise<T>;
  text(): Promise<string>;
}

export type AppRouteHandler<T = NextResponseData> = (
  req: NextRequest
) => Promise<Response> | Response;

export type AppRouteSecuredHandler<T = NextResponseData> = (
  ...modules: SecurityModule[]
) => AppRouteHandler<T>;

// Server action types
export type ServerActionFn = (...args: any[]) => Promise<any>;
export type ServerActionSecuredFn<T extends ServerActionFn> = (...modules: SecurityModule[]) => T;

// Edge middleware type
export type EdgeMiddlewareHandler = (req: NextRequest) => Promise<Response>;

// Response proxy type to simulate response for App Router/Edge
export interface ResponseProxy {
  headersSent: boolean;
  writableEnded: boolean;
  statusCode: number;
  headers: Headers;
  status(code: number): ResponseProxy;
  setHeader(name: string, value: string): ResponseProxy;
  json(body: any): Response;
}

// Error metadata type
export interface SecurityErrorMetadata {
  module: string;
  reason: string;
  type?: string;
  timestamp: string;
  severity?: string;
  details: Record<string, any>;
}

// Error response data type
export interface SecurityErrorResponse {
  error: string;
  blocked: boolean;
  meta: SecurityErrorMetadata;
  statusCode: number;
}
