/**
 * AWS Lambda Local Development Wrapper
 * 
 * This module provides a local development environment for AWS Lambda functions,
 * simulating the Lambda runtime environment within a Docker container.
 * 
 * Features:
 * - API Gateway v1 & v2 event simulation
 * - Lambda context simulation
 * - CORS support
 * - Response compression
 * - Streaming responses
 * - Health checks
 * - Graceful shutdown
 * 
 * Environment Variables:
 * - AWS_LWA_PORT: Main server port (default: 8080)
 * - AWS_LWA_READINESS_CHECK_PORT: Health check port
 * - AWS_LWA_INVOKE_MODE: Execution mode
 * - AWS_LWA_ENABLE_COMPRESSION: Enable gzip compression
 * - NODE_ENV/DENO_ENV: Development mode flag
 * 
 * @example
 * ```typescript
 * import { startLambdaServer } from './mod.ts';
 * 
 * await startLambdaServer({
 *   httpHandler: async (event, context) => {
 *     return {
 *       statusCode: 200,
 *       body: JSON.stringify({ message: 'Hello from Lambda!' })
 *     };
 *   },
 *   logger: console,
 * });
 * ```
 */

import type { Logger } from "npm:@aws-lambda-powertools/logger";
export type AWSLogger = Logger;

import type {
  Context,
  APIGatewayProxyEvent,
  APIGatewayProxyEventV2,
  APIGatewayProxyResult,
  APIGatewayProxyResultV2,
  APIGatewayEventRequestContext,
  APIGatewayEventRequestContextV2,
} from "npm:@types/aws-lambda";

const nodeEnv = Deno.env.get("DENO_ENV") ?? Deno.env.get("NODE_ENV");
const isNodeDevelopment = nodeEnv === "development";

// Add compression helper function at the top
const compressResponse = async (data: string | Record<string, unknown>): Promise<Uint8Array> => {
  try {
    const stringData = typeof data === 'string' ? data : JSON.stringify(data);
    const encoder = new TextEncoder();
    const stream = new CompressionStream('gzip');
    const writer = stream.writable.getWriter();
    await writer.write(encoder.encode(stringData));
    await writer.close();
    return new Uint8Array(await new Response(stream.readable).arrayBuffer());
  } catch (error) {
    throw new Error('Failed to compress response', { cause: error });
  }
};

export const parseRequestContext = (req: Request): APIGatewayEventRequestContextV2 | APIGatewayEventRequestContext | null => {
  const input = 
    req.headers.get("x-amzn-request-context")?.trim() || 
    req.headers.get("X-Amzn-Request-Context")?.trim() || 
    "{}";

  try {
    const contents = JSON.parse(input);
    if (typeof contents !== "object" || !contents) {
      throw new Error(`Request context must be an object, got: ${input}`);
    }

    // Check if it's a v2 request context by looking for v2-specific fields
    if ('apiId' in contents && 'http' in contents) {
      return contents as APIGatewayEventRequestContextV2;
    }

    // Otherwise treat as v1 request context
    return contents as APIGatewayEventRequestContext;

  } catch (e) {
    if (!(e instanceof Error)) throw e;
    throw new Error(`Malformed JSON in request context: ${input}`, {
      cause: e,
    });
  }
};

const parseContext = (req: Request): Context => {
  const input = 
    req.headers.get("x-amzn-lambda-context")?.trim() || 
    req.headers.get("X-Amzn-Lambda-Context")?.trim() || 
    "{}";

  try {
    const contents = JSON.parse(input);
    if (typeof contents !== "object" || !contents) {
      throw new Error(`Lambda context must be an object, got: ${input}`);
    }

    const {
      request_id,
      invoked_function_arn,
      client_context,
      identity,
      callbackWaitsForEmptyEventLoop,
      getRemainingTimeInMillis,
      env_config = {},
    // deno-lint-ignore no-explicit-any
    } = contents as Record<string, any>;

    const { function_name, memory, version, log_stream, log_group } = env_config;

    const noop = () => {};

    const constructedArn = invoked_function_arn || (() => {
      const region = Deno.env.get("AWS_REGION")?.trim() || 
                    Deno.env.get("AWS_DEFAULT_REGION")?.trim();
      const accountId = Deno.env.get("AWS_ACCOUNT_ID")?.trim();
      const functionName = (
        function_name || 
        Deno.env.get("AWS_LAMBDA_FUNCTION_NAME") ||
        Deno.env.get("_HANDLER")?.split('.')[0]
      )?.trim();

      if (!region || !/^[a-z]{2}-[a-z]+-\d+$/.test(region)) return undefined;
      if (!accountId || !/^\d{12}$/.test(accountId)) return undefined;
      if (!functionName || !/^[a-zA-Z0-9-_]+$/.test(functionName)) return undefined;

      return `arn:aws:lambda:${region}:${accountId}:function:${functionName}`;
    })();

    const timeoutMs = parseInt(
      Deno.env.get("AWS_LAMBDA_FUNCTION_TIMEOUT") || 
      "60"
    ) * 1000;
    const startTime = Date.now();
    const deadline = startTime + timeoutMs;

    // Return the standard context object
    return {
      functionName: function_name || 
                   Deno.env.get("AWS_LAMBDA_FUNCTION_NAME") ||
                   Deno.env.get("_HANDLER")?.split('.')[0] || '',
      functionVersion: version || 
                      Deno.env.get("AWS_LAMBDA_FUNCTION_VERSION") || '',
      invokedFunctionArn: invoked_function_arn || 
                         constructedArn || 
                         Deno.env.get("AWS_LAMBDA_FUNCTION_ARN") || '',
      memoryLimitInMB: memory || 
                       Deno.env.get("AWS_LAMBDA_FUNCTION_MEMORY_SIZE") || '',
      awsRequestId: request_id || 
                    crypto.randomUUID(),
      logGroupName: log_group || 
                    Deno.env.get("AWS_LAMBDA_LOG_GROUP_NAME") || '',
      logStreamName: log_stream || 
                     Deno.env.get("AWS_LAMBDA_LOG_STREAM_NAME") || '',
      identity: identity || undefined,
      clientContext: client_context || undefined,
      callbackWaitsForEmptyEventLoop: callbackWaitsForEmptyEventLoop || true,
      getRemainingTimeInMillis: getRemainingTimeInMillis || (() => Math.max(0, deadline - Date.now())),
      done: noop,
      fail: noop,
      succeed: noop,
    } as Context;
  } catch (_error) {
    // Instead of throwing an error, return a default context
    const timeoutMs = parseInt(
      Deno.env.get("AWS_LAMBDA_FUNCTION_TIMEOUT") || 
      "60"
    ) * 1000;
    const startTime = Date.now();
    const deadline = startTime + timeoutMs;
    const noop = () => {};

    return {
      functionName: Deno.env.get("AWS_LAMBDA_FUNCTION_NAME") ||
                   Deno.env.get("_HANDLER")?.split('.')[0] || '',
      functionVersion: Deno.env.get("AWS_LAMBDA_FUNCTION_VERSION") || '',
      invokedFunctionArn: Deno.env.get("AWS_LAMBDA_FUNCTION_ARN") || '',
      memoryLimitInMB: Deno.env.get("AWS_LAMBDA_FUNCTION_MEMORY_SIZE") || '',
      awsRequestId: crypto.randomUUID(),
      logGroupName: Deno.env.get("AWS_LAMBDA_LOG_GROUP_NAME") || '',
      logStreamName: Deno.env.get("AWS_LAMBDA_LOG_STREAM_NAME") || '',
      identity: undefined,
      clientContext: undefined,
      callbackWaitsForEmptyEventLoop: true,
      getRemainingTimeInMillis: () => Math.max(0, deadline - Date.now()),
      done: noop,
      fail: noop,
      succeed: noop,
    } as Context;
  }
};

export const parseJson = (input: string): [Error | null, unknown] => {
  try {
    return [null, JSON.parse(input)];
  } catch (e) {
    if (!(e instanceof Error)) throw e;
    return [e, null];
  }
};

const createCorsHeaders = (
  hasRequestContext: boolean
): Record<string, string> => ({
  ...(hasRequestContext
    ? {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
      }
    : {}),
});

export const handleWithTimeout = async (
  promise: Promise<Response>,
  context: Context,
  timeoutBuffer = 100
): Promise<Response> => {
  const remainingTime = context.getRemainingTimeInMillis();
  if (remainingTime <= timeoutBuffer) {
    throw new Error('Insufficient time remaining for execution');
  }

  const timeout = new Promise<Response>((_, reject) => {
    const timeoutMs = remainingTime - timeoutBuffer;
    setTimeout(() => {
      reject(new Error(`Lambda function timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });

  return await Promise.race([promise, timeout]);
};

const getHeader = (req: Request, names: string[]): string | null => {
  for (const name of names) {
    const value = req.headers.get(name)?.trim();
    if (value) return value;
  }
  return null;
};

const constructApiGatewayV2Event = (
  req: Request,
  bodyText: string,
  url: URL,
  requestContextV2: APIGatewayEventRequestContextV2,
): APIGatewayProxyEventV2 => {
  const accountId = requestContextV2?.accountId || Deno.env.get("AWS_ACCOUNT_ID") || "";
  const stage = requestContextV2?.stage || Deno.env.get("AWS_LAMBDA_FUNCTION_STAGE") || "prod";
  
  return {
    version: '2.0',
    rawPath: url.pathname,
    routeKey: requestContextV2?.routeKey ?? '$default',
    rawQueryString: url.search.slice(1),
    cookies: req.headers.get('cookie')?.split('; ') || 
             req.headers.get('Cookie')?.split('; ') || [],
    isBase64Encoded: false,
    requestContext: {
      ...requestContextV2,
      accountId,
      apiId: requestContextV2?.apiId ?? Deno.env.get("AWS_API_GATEWAY_ID") ?? "",
      authentication: requestContextV2?.authentication ?? {
        clientCert: {
          clientCertPem: getHeader(req, ["x-amzn-client-cert-pem", "X-Amzn-Client-Cert-Pem"]) || null,
          issuerDN: getHeader(req, ["x-amzn-client-cert-issuer-dn", "X-Amzn-Client-Cert-Issuer-Dn"]) || null,
          serialNumber: getHeader(req, ["x-amzn-client-cert-serial-number", "X-Amzn-Client-Cert-Serial-Number"]) || null,
          subjectDN: getHeader(req, ["x-amzn-client-cert-subject-dn", "X-Amzn-Client-Cert-Subject-Dn"]) || null,
          validity: {
            notAfter: getHeader(req, ["x-amzn-client-cert-not-after", "X-Amzn-Client-Cert-Not-After"]) || null,
            notBefore: getHeader(req, ["x-amzn-client-cert-not-before", "X-Amzn-Client-Cert-Not-Before"]) || null
          }
        }
      },
      domainName: requestContextV2?.domainName ?? (
        req.headers.get("host") || req.headers.get("Host") || 
        req.headers.get("x-forwarded-host") || req.headers.get("X-Forwarded-Host") || ""
      ),
      domainPrefix: requestContextV2?.domainPrefix ?? (
        req.headers.get("host")?.split(".")[0] || req.headers.get("Host")?.split(".")[0] || ""
      ),
      http: {
        method: req.method,
        path: url.pathname,
        protocol: req.headers.get('x-forwarded-proto') || 
                 req.headers.get('X-Forwarded-Proto') || 'https',
        sourceIp: req.headers.get("x-forwarded-for")?.split(",")[0] || 
                 req.headers.get("X-Forwarded-For")?.split(",")[0] || 
                 req.headers.get("x-real-ip") || 
                 req.headers.get("X-Real-Ip") || 
                 "0.0.0.0",
        userAgent: req.headers.get('user-agent') || 
                  req.headers.get('User-Agent') || '',
      },
      requestId: requestContextV2?.requestId ?? crypto.randomUUID(),
      routeKey: requestContextV2?.routeKey ?? '$default',
      stage,
      time: requestContextV2?.time ?? new Date().toISOString(),
      timeEpoch: requestContextV2?.timeEpoch ?? Date.now(),
    },
    headers: Object.fromEntries(req.headers),
    queryStringParameters: Object.fromEntries(url.searchParams),
    body: bodyText,
  } as APIGatewayProxyEventV2;
};

const constructApiGatewayV1Event = (
  req: Request,
  bodyText: string,
  url: URL,
  requestContextV1: APIGatewayEventRequestContext,
): APIGatewayProxyEvent => {
  const accountId = requestContextV1?.accountId || Deno.env.get("AWS_ACCOUNT_ID") || "";
  
  return {
    path: url.pathname,
    resource: requestContextV1?.resourcePath || url.pathname,
    httpMethod: req.method,
    headers: Object.fromEntries(req.headers),
    multiValueHeaders: Object.fromEntries(
      [...req.headers.entries()].map(([key, value]) => [key, [value]])
    ),
    queryStringParameters: Object.fromEntries(url.searchParams),
    multiValueQueryStringParameters: Object.fromEntries(
      [...url.searchParams.entries()].map(([key, value]) => [key, [value]])
    ),
    pathParameters: "pathParameters" in requestContextV1 && requestContextV1?.pathParameters || null,
    stageVariables: "stageVariables" in requestContextV1 && requestContextV1?.stageVariables || null,
    body: bodyText,
    isBase64Encoded: false,
    requestContext: {
      accountId,
      apiId: requestContextV1?.apiId || Deno.env.get("AWS_API_GATEWAY_ID") || "",
      authorizer: requestContextV1?.authorizer || null,
      protocol: req.headers.get("x-forwarded-proto") || req.headers.get("X-Forwarded-Proto") || "https",
      resourceId: requestContextV1?.resourceId || "",
      resourcePath: requestContextV1?.resourcePath || url.pathname,
      httpMethod: req.method,
      requestId: requestContextV1?.requestId || crypto.randomUUID(),
      requestTime: requestContextV1?.requestTime || new Date().toISOString(),
      requestTimeEpoch: requestContextV1?.requestTimeEpoch || Date.now(),
      stage: requestContextV1?.stage || Deno.env.get("AWS_LAMBDA_FUNCTION_STAGE") || "prod",
      identity: {
        accessKey: requestContextV1?.identity?.accessKey || Deno.env.get("AWS_ACCESS_KEY_ID") || null,
        accountId: requestContextV1?.identity?.accountId || accountId || null,
        apiKey: requestContextV1?.identity?.apiKey || req.headers.get("x-api-key") || req.headers.get("X-Api-Key") || null,
        apiKeyId: requestContextV1?.identity?.apiKeyId || null,
        caller: requestContextV1?.identity?.caller || Deno.env.get("AWS_CALLER_ID") || null,
        cognitoAuthenticationProvider: requestContextV1?.identity?.cognitoAuthenticationProvider || 
          req.headers.get("x-amzn-cognito-authentication-provider") || req.headers.get("X-Amzn-Cognito-Authentication-Provider") || null,
        cognitoAuthenticationType: requestContextV1?.identity?.cognitoAuthenticationType || 
          req.headers.get("x-amzn-cognito-authentication-type") || req.headers.get("X-Amzn-Cognito-Authentication-Type") || null,
        cognitoIdentityId: requestContextV1?.identity?.cognitoIdentityId || 
          req.headers.get("x-amzn-cognito-identity-id") || req.headers.get("X-Amzn-Cognito-Identity-Id") || null,
        cognitoIdentityPoolId: requestContextV1?.identity?.cognitoIdentityPoolId || 
          req.headers.get("x-amzn-cognito-identity-pool-id") || req.headers.get("X-Amzn-Cognito-Identity-Pool-Id") || null,
        principalOrgId: requestContextV1?.identity?.principalOrgId || 
          req.headers.get("x-amzn-principal-org-id") || req.headers.get("X-Amzn-Principal-Org-Id") || null,
        sourceIp: requestContextV1?.identity?.sourceIp || 
          req.headers.get("x-forwarded-for")?.split(",")[0] || 
          req.headers.get("X-Forwarded-For")?.split(",")[0] || 
          req.headers.get("x-real-ip") || 
          req.headers.get("X-Real-Ip") || 
          "0.0.0.0",
        user: requestContextV1?.identity?.user || 
          req.headers.get("x-amzn-oidc-identity") || req.headers.get("X-Amzn-Oidc-Identity") || 
          req.headers.get("x-amzn-oidc-data")?.split(".")[1] || req.headers.get("X-Amzn-Oidc-Data")?.split(".")[1] || null,
        userAgent: requestContextV1?.identity?.userAgent || req.headers.get("user-agent") || req.headers.get("User-Agent") || null,
        userArn: requestContextV1?.identity?.userArn || 
          req.headers.get("x-amzn-oidc-identity-arn") || req.headers.get("X-Amzn-Oidc-Identity-Arn") || 
          req.headers.get("x-amzn-iam-user-arn") || req.headers.get("X-Amzn-Iam-User-Arn") || null,
        clientCert: requestContextV1?.identity?.clientCert || {
          clientCertPem: getHeader(req, ["x-amzn-client-cert-pem", "X-Amzn-Client-Cert-Pem"]) || null,
          issuerDN: getHeader(req, ["x-amzn-client-cert-issuer-dn", "X-Amzn-Client-Cert-Issuer-Dn"]) || null,
          serialNumber: getHeader(req, ["x-amzn-client-cert-serial-number", "X-Amzn-Client-Cert-Serial-Number"]) || null,
          subjectDN: getHeader(req, ["x-amzn-client-cert-subject-dn", "X-Amzn-Client-Cert-Subject-Dn"]) || null,
          validity: {
            notAfter: getHeader(req, ["x-amzn-client-cert-not-after", "X-Amzn-Client-Cert-Not-After"]) || null,
            notBefore: getHeader(req, ["x-amzn-client-cert-not-before", "X-Amzn-Client-Cert-Not-Before"]) || null
          }
        }
      },
      path: url.pathname,
      domainName: requestContextV1?.domainName || 
        req.headers.get("host") || req.headers.get("Host") || 
        req.headers.get("x-forwarded-host") || req.headers.get("X-Forwarded-Host") || "",
      domainPrefix: requestContextV1?.domainPrefix || 
        req.headers.get("host")?.split(".")[0] || req.headers.get("Host")?.split(".")[0] || "",
      extendedRequestId: requestContextV1?.extendedRequestId || crypto.randomUUID(),
      apiGateway: true,
    },
  } as APIGatewayProxyEvent;
};

const constructApiGatewayEvent = (
  req: Request,
  bodyText: string,
  url: URL,
  requestContext: APIGatewayEventRequestContextV2 | APIGatewayEventRequestContext | null
): APIGatewayProxyEvent | APIGatewayProxyEventV2 => {
  return requestContext?.apiId !== undefined 
    ? constructApiGatewayV2Event(req, bodyText, url, requestContext as APIGatewayEventRequestContextV2)
    : constructApiGatewayV1Event(req, bodyText, url, requestContext as APIGatewayEventRequestContext);
};

export const serveHttpLambda = (
  handler: (
    event: APIGatewayProxyEvent | APIGatewayProxyEventV2,
    context: Context
  ) => Promise<APIGatewayProxyResult | APIGatewayProxyResultV2>,
  logger?: AWSLogger
): ((req: Request) => Promise<Response>) => {
  return async (req: Request): Promise<Response> => {
    try {
      logger?.debug('Handling HTTP Lambda request', {
        method: req.method,
        url: req.url,
        headers: Object.fromEntries(req.headers)
      });

      // Handle preflight CORS requests
      if (req.method === "OPTIONS") {
        logger?.debug('Handling CORS preflight request');
        return new Response(null, {
          status: 204,
          headers: {
            ...createCorsHeaders(true),
            "Content-Length": "0",
            "Cache-Control": "max-age=86400"
          },
        });
      }

      logger?.debug('Parsing request context and Lambda context');
      const requestContext = parseRequestContext(req) || null;
      const context = parseContext(req) || ({} as Context);

      logger?.debug('Reading request body and constructing event');
      const bodyText = await req.text();
      const url = new URL(req.url);

      const event = constructApiGatewayEvent(req, bodyText, url, requestContext);
      logger?.debug('Constructed API Gateway event', { 
        eventType: 'apiId' in event.requestContext ? 'v2' : 'v1',
        path: url.pathname,
        method: req.method
      });

      logger?.debug('Calling Lambda handler');
      const result = await handler(event, context);
      logger?.debug('Lambda handler completed', {
        statusCode: typeof result === 'object' && result !== null && 'statusCode' in result 
          ? result.statusCode 
          : 200
      });

      const hasRequestContext = Boolean(
        req.headers.get("x-amzn-request-context") ||
        req.headers.get("X-Amzn-Request-Context")
      );
      
      const baseHeaders: Record<string, string> = {
        "Content-Type": "application/json",
        "X-Content-Type-Options": "nosniff",
        ...createCorsHeaders(hasRequestContext),
      };

      // Handle regular response
      const responseBody = JSON.stringify(result);
      const isCompressionEnabled = Deno.env.get("AWS_LWA_ENABLE_COMPRESSION") === "true";

      if (isCompressionEnabled) {
        const compressed = await compressResponse(responseBody);
        return new Response(compressed, { 
          headers: {
            ...baseHeaders,
            "Content-Encoding": "gzip",
          }
        });
      }

      return new Response(responseBody, { headers: baseHeaders });
    } catch (error: unknown) {
      logger?.error("Lambda handler error", {
        error: error instanceof Error ? error : new Error(String(error)),
        path: new URL(req.url).pathname,
        method: req.method,
        message: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        timestamp: new Date().toISOString()
      });

      const hasRequestContext = Boolean(
        req.headers.get("x-amzn-request-context") ||
        req.headers.get("X-Amzn-Request-Context")
      );

      return new Response(
        JSON.stringify({
          message: "Internal Server Error",
          ...(isNodeDevelopment && {
            error: error instanceof Error ? error.message : String(error),
          }),
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json",
            ...createCorsHeaders(hasRequestContext),
          },
        }
      );
    }
  };
};

// Update serveEventLambda to handle event source context
export const serveEventLambda = (
  // deno-lint-ignore no-explicit-any
  handler: (event: any, context: Context) => Promise<any>,
  logger?: AWSLogger
): (req: Request) => Promise<Response> => {
  return async (req: Request): Promise<Response> => {
    try {
      logger?.debug('Handling event Lambda request', {
        method: req.method,
        url: req.url
      });

      if (req.method !== "POST") {
        logger?.warn("Method not allowed for event handler", {
          path: new URL(req.url).pathname,
          method: req.method
        });
        return new Response(JSON.stringify({ message: "Method Not Allowed" }), {
          status: 405,
        });
      }

      logger?.debug('Reading event payload');
      const eventInput = await req.text().catch(() => null);
      const [error, event] = eventInput 
        ? parseJson(eventInput)
        : [null, {}];

      if (error) {
        logger?.error("Malformed JSON in Lambda event", {
          path: new URL(req.url).pathname,
          rawInput: eventInput,
          error: error instanceof Error ? error.message : String(error)
        });
        return new Response(
          JSON.stringify({ message: `Invalid JSON payload: ${eventInput}` }),
          {
            status: 400,
            headers: { "Content-Type": "application/json" },
          }
        );
      }
    
      if (typeof event !== "object") {
        throw new Error(`Lambda event is not an object: ${event}`);
      }

      logger?.debug('Parsing Lambda context');
      const context = parseContext(req) || ({} as Context);

      logger?.debug('Invoking event handler');
      const result = await handler(event, context);
      logger?.debug('Event handler completed successfully', {
        resultType: typeof result
      });

      return new Response(JSON.stringify(result), {
        headers: {
          "Content-Type": "application/json",
          "X-Content-Type-Options": "nosniff",
        },
      });
    } catch (error) {
      logger?.error("Event handler error", {
        error: error instanceof Error ? error : new Error(String(error)),
        path: new URL(req.url).pathname,
        method: req.method,
        message: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        timestamp: new Date().toISOString()
      });
      return new Response(
        JSON.stringify({
          message: "Internal Server Error",
          ...(isNodeDevelopment && {
            error: error instanceof Error ? error.message : String(error),
          }),
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    }
  };
};

// Add type definitions for commonly used types
type ServerConfig = {
  hostname: string;
  onError: (error: unknown) => Response;
};

type DenoServer = ReturnType<typeof Deno.serve>;

type LambdaServerOptions = {
  // deno-lint-ignore no-explicit-any
  eventHandler?: <T = any, R = any>(
    event: T,
    context: Context
  ) => Promise<R>,
  httpHandler?: (
    event: APIGatewayProxyEvent | APIGatewayProxyEventV2, 
    context: Context
  ) => Promise<APIGatewayProxyResult | APIGatewayProxyResultV2>,
  healthHandler?: (req: Request) => Response | Promise<Response>,
  logger?: AWSLogger,
  onShutdown?: () => Promise<void> | void,
};

const defaultHealthHandler = (_req: Request): Response => {
  return new Response(JSON.stringify({ status: "ok" }), {
    headers: { "Content-Type": "application/json" },
  });
};

export const startLambdaServer = ({
  eventHandler,
  httpHandler,
  healthHandler = defaultHealthHandler,
  logger,
  onShutdown,
}: LambdaServerOptions) => () => {
  logger?.info('Initializing Lambda server', {
    hasEventHandler: !!eventHandler,
    hasHttpHandler: !!httpHandler,
    hasCustomHealthHandler: healthHandler !== defaultHealthHandler,
    hasShutdownHandler: !!onShutdown
  });

  let mainServer = {} as DenoServer;
  let healthServer = {} as DenoServer;

  // Add shutdown handler
  // deno-lint-ignore require-await
  const handleShutdown = async () => {
    // Avoid logging during shutdown
    try {
      // Any cleanup logic here
      return true;
    } catch (_error) {
      return false;
    }
  };

  const serverConfig = {
    hostname: Deno.env.get("AWS_LWA_LISTEN") || "0.0.0.0",
    onError: (error: unknown) => {
      if (logger) {
        logger.error("Server error", {
          error: error instanceof Error ? error : new Error(String(error)),
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined
        });
      }
      return new Response(
        JSON.stringify({
          message: "Internal Server Error",
          ...(isNodeDevelopment && {
            error: error instanceof Error ? error.message : String(error),
          }),
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    },
  };

  // Get environment variables with fallbacks
  const mainPort = (() => {
    const port = parseInt(
      Deno.env.get("AWS_LWA_PORT") ?? Deno.env.get("PORT") ?? "8080"
    );
    if (port === 9001 || port === 3000) {
      throw new Error(`Port ${port} is reserved and cannot be used`);
    }
    return port;
  })();

  const readinessPort = (() => {
    const port = parseInt(
      Deno.env.get("AWS_LWA_READINESS_CHECK_PORT") ||
        Deno.env.get("READINESS_CHECK_PORT") ||
        String(mainPort)
    );
    if (port === 9001 || port === 3000) {
      throw new Error(`Port ${port} is reserved and cannot be used`);
    }
    return port;
  })();

  const readinessPath =
    Deno.env.get("AWS_LWA_READINESS_CHECK_PATH") ||
    Deno.env.get("READINESS_CHECK_PATH") ||
    "/";

  // Update handler to properly await all async operations
  const mainHandler = async (req: Request): Promise<Response> => {
    const pathname = new URL(req.url).pathname;
    const eventsPath = Deno.env.get("AWS_LWA_PASS_THROUGH_PATH") || "/events";

    logger?.debug('Received request', {
      method: req.method,
      path: pathname,
      headers: Object.fromEntries(req.headers)
    });

    try {
      // Handle health check requests
      if (
        req.method === "GET" &&
        pathname === readinessPath &&
        mainPort === readinessPort
      ) {
        return await healthHandler(req);
      }

      // Handle non-http Lambda events
      if (pathname === eventsPath && req.method === "POST") {
        logger?.debug('Routing to event handler');
        if (!eventHandler) {
          logger?.warn("Event handler not configured");
          return new Response("Handler not found", { status: 404 });
        }
        return await serveEventLambda(eventHandler, logger)(req);
      } else if (pathname === eventsPath && req.method !== "POST") {
        logger?.warn(`Method ${req.method} not allowed for events path ${eventsPath}`, {
          path: pathname,
          method: req.method
        });
        return new Response("Method Not Allowed", { status: 405 });
      }

      // Handle all other paths with HTTP handler
      if (httpHandler) {
        logger?.debug('Routing to HTTP handler');
        return await serveHttpLambda(httpHandler, logger)(req);
      }

      // No handler configured
      logger?.warn("No handler configured for request", {
        path: pathname,
        method: req.method
      });
      return new Response(JSON.stringify({ message: "Handler not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    } catch (error) {
      logger?.error("Unhandled server error", {
        error: error instanceof Error ? error : new Error(String(error)),
        path: pathname,
        method: req.method,
        message: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        timestamp: new Date().toISOString()
      });
      return new Response(
        JSON.stringify({
          message: "Internal Server Error",
          ...(isNodeDevelopment && {
            error: error instanceof Error ? error.message : String(error),
          }),
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
    }
  };

  // Start servers with the updated handler
  mainServer = Deno.serve({
    ...serverConfig,
    port: mainPort,
    handler: mainHandler,
    onListen(addr) {
      if (logger) {
        logger.info("Server started", {
          hostname: addr.hostname,
          port: addr.port,
          message: `Application listening on ${addr.hostname}:${addr.port}`
        });
      }
    },
  });

  // Start separate health check server if ports differ
  if (mainPort !== readinessPort) {
    healthServer = Deno.serve({
      ...serverConfig,
      port: readinessPort,
      handler: async (req: Request) => {
        const pathname = new URL(req.url).pathname;

        if (req.method === "GET" && pathname === readinessPath) {
          return await healthHandler(req);
        }

        if (logger) {
          logger.error("Health check failed", {
            status: 404,
            method: req.method,
            path: pathname,
            expectedPath: readinessPath,
            message: `Health check only available at '${readinessPath}'`,
            requestUrl: req.url
          });
        }

        return new Response(JSON.stringify({ message: "Not Found" }), {
          status: 404,
          headers: { "Content-Type": "application/json" },
        });
      },
      onListen(addr) {
        if (logger) {
          logger.info("Health check server started", {
            hostname: addr.hostname,
            port: addr.port,
            path: readinessPath,
            message: `Health check listening on ${addr.hostname}:${addr.port}${readinessPath}`
          });
        }
      },
    });
  }

  return {
    close: handleShutdown,
    mainServer,
    healthServer,
  };
};

