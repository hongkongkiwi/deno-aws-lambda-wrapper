import type { Logger } from "npm:@aws-lambda-powertools/logger";
import type {
  APIGatewayEventRequestContext,
  APIGatewayEventRequestContextV2,
  APIGatewayProxyEvent,
  APIGatewayProxyEventV2,
  APIGatewayProxyResult,
  APIGatewayProxyResultV2,
  Context,
} from "npm:@types/aws-lambda";

const nodeEnv = Deno.env.get("DENO_ENV") ?? Deno.env.get("NODE_ENV");
const isNodeDevelopment = nodeEnv === "development";

// Add compression helper function at the top
const compressResponse = async (
  data: string | Record<string, unknown>,
): Promise<Uint8Array> => {
  try {
    const stringData = typeof data === "string" ? data : JSON.stringify(data);
    const encoder = new TextEncoder();
    const stream = new CompressionStream("gzip");
    const writer = stream.writable.getWriter();
    await writer.write(encoder.encode(stringData));
    await writer.close();
    return new Uint8Array(await new Response(stream.readable).arrayBuffer());
  } catch (error) {
    throw new Error("Failed to compress response", { cause: error });
  }
};

export const parseRequestContext = (
  req: Request,
): APIGatewayEventRequestContextV2 | APIGatewayEventRequestContext | null => {
  const input = getHeader(req, "x-amzn-request-context")?.trim() || "{}";

  try {
    const contents = JSON.parse(input);
    if (typeof contents !== "object" || !contents) {
      throw new Error(`Request context must be an object, got: ${input}`);
    }

    // Check if it's a v2 request context by looking for v2-specific fields
    if ("apiId" in contents && "http" in contents) {
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

const getHeader = (req: Request, name: string): string | null => {
  return req.headers.get(name)?.trim() || null;
};

const parseContext = (req: Request): Context => {
  const input = getHeader(req, "x-amzn-lambda-context")?.trim() || "{}";

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

    const { function_name, memory, version, log_stream, log_group } =
      env_config;

    const noop = () => {};

    const constructedArn = invoked_function_arn ||
      (() => {
        const region = Deno.env.get("AWS_REGION")?.trim() ||
          Deno.env.get("AWS_DEFAULT_REGION")?.trim();
        const accountId = Deno.env.get("AWS_ACCOUNT_ID")?.trim();
        const functionName = (
          function_name ||
          Deno.env.get("AWS_LAMBDA_FUNCTION_NAME") ||
          Deno.env.get("_HANDLER")?.split(".")[0]
        )?.trim();

        if (!region || !/^[a-z]{2}-[a-z]+-\d+$/.test(region)) return undefined;
        if (!accountId || !/^\d{12}$/.test(accountId)) return undefined;
        if (!functionName || !/^[a-zA-Z0-9-_]+$/.test(functionName)) {
          return undefined;
        }

        return `arn:aws:lambda:${region}:${accountId}:function:${functionName}`;
      })();

    const timeoutMs =
      parseInt(Deno.env.get("AWS_LAMBDA_FUNCTION_TIMEOUT") || "60") * 1000;
    const startTime = Date.now();
    const deadline = startTime + timeoutMs;

    // Return the standard context object
    return {
      functionName: function_name ||
        Deno.env.get("AWS_LAMBDA_FUNCTION_NAME") ||
        Deno.env.get("_HANDLER")?.split(".")[0] ||
        "",
      functionVersion: version || Deno.env.get("AWS_LAMBDA_FUNCTION_VERSION") ||
        "",
      invokedFunctionArn: invoked_function_arn ||
        constructedArn ||
        Deno.env.get("AWS_LAMBDA_FUNCTION_ARN") ||
        "",
      memoryLimitInMB: memory ||
        Deno.env.get("AWS_LAMBDA_FUNCTION_MEMORY_SIZE") || "",
      awsRequestId: request_id || crypto.randomUUID(),
      logGroupName: log_group || Deno.env.get("AWS_LAMBDA_LOG_GROUP_NAME") ||
        "",
      logStreamName: log_stream || Deno.env.get("AWS_LAMBDA_LOG_STREAM_NAME") ||
        "",
      identity: identity || undefined,
      clientContext: client_context || undefined,
      callbackWaitsForEmptyEventLoop: callbackWaitsForEmptyEventLoop || true,
      getRemainingTimeInMillis: getRemainingTimeInMillis ||
        (() => Math.max(0, deadline - Date.now())),
      done: noop,
      fail: noop,
      succeed: noop,
    } as Context;
  } catch (_error) {
    // Instead of throwing an error, return a default context
    const timeoutMs =
      parseInt(Deno.env.get("AWS_LAMBDA_FUNCTION_TIMEOUT") || "60") * 1000;
    const startTime = Date.now();
    const deadline = startTime + timeoutMs;
    const noop = () => {};

    return {
      functionName: Deno.env.get("AWS_LAMBDA_FUNCTION_NAME") ||
        Deno.env.get("_HANDLER")?.split(".")[0] ||
        "",
      functionVersion: Deno.env.get("AWS_LAMBDA_FUNCTION_VERSION") || "",
      invokedFunctionArn: Deno.env.get("AWS_LAMBDA_FUNCTION_ARN") || "",
      memoryLimitInMB: Deno.env.get("AWS_LAMBDA_FUNCTION_MEMORY_SIZE") || "",
      awsRequestId: crypto.randomUUID(),
      logGroupName: Deno.env.get("AWS_LAMBDA_LOG_GROUP_NAME") || "",
      logStreamName: Deno.env.get("AWS_LAMBDA_LOG_STREAM_NAME") || "",
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

const createCorsHeaders = (
  hasRequestContext: boolean,
): Record<string, string> => ({
  ...(hasRequestContext
    ? {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    }
    : {}),
});

const constructApiGatewayV2Event = (
  req: Request,
  bodyText: string,
  url: URL,
  requestContextV2: APIGatewayEventRequestContextV2,
): APIGatewayProxyEventV2 => {
  const accountId = requestContextV2?.accountId ||
    Deno.env.get("AWS_ACCOUNT_ID") || "";
  const stage = requestContextV2?.stage ||
    Deno.env.get("AWS_LAMBDA_FUNCTION_STAGE") ||
    "prod";

  return {
    version: "2.0",
    rawPath: url.pathname,
    routeKey: requestContextV2?.routeKey ?? "$default",
    rawQueryString: url.search.slice(1),
    cookies: getHeader(req, "cookie")?.split("; ") || [],
    isBase64Encoded: false,
    requestContext: {
      ...requestContextV2,
      accountId,
      apiId: requestContextV2?.apiId ?? Deno.env.get("AWS_API_GATEWAY_ID") ?? "",
      authentication: requestContextV2?.authentication ?? {
        clientCert: {
          clientCertPem: getHeader(req, "x-amzn-client-cert-pem") || null,
          issuerDN: getHeader(req, "x-amzn-client-cert-issuer-dn") || null,
          serialNumber: getHeader(req, "x-amzn-client-cert-serial-number") || null,
          subjectDN: getHeader(req, "x-amzn-client-cert-subject-dn") || null,
          validity: {
            notAfter: getHeader(req, "x-amzn-client-cert-not-after") || null,
            notBefore: getHeader(req, "x-amzn-client-cert-not-before") || null,
          },
        },
      },
      domainName: requestContextV2?.domainName ??
        (getHeader(req, "host") || getHeader(req, "x-forwarded-host") || ""),
      domainPrefix: requestContextV2?.domainPrefix ??
        (getHeader(req, "host")?.split(".")[0] ||
          getHeader(req, "x-forwarded-host")?.split(".")[0] ||
          ""),
      http: {
        method: req.method,
        path: url.pathname,
        protocol: getHeader(req, "x-forwarded-proto") || "https",
        sourceIp: getHeader(req, "x-forwarded-for")?.split(",")[0] ||
          getHeader(req, "x-real-ip") ||
          "0.0.0.0",
        userAgent: getHeader(req, "user-agent") || "",
      },
      requestId: requestContextV2?.requestId ?? crypto.randomUUID(),
      routeKey: requestContextV2?.routeKey ?? "$default",
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
  const accountId = requestContextV1?.accountId ||
    Deno.env.get("AWS_ACCOUNT_ID") || "";

  return {
    path: url.pathname,
    resource: requestContextV1?.resourcePath || url.pathname,
    httpMethod: req.method,
    headers: Object.fromEntries(req.headers),
    multiValueHeaders: Object.fromEntries(
      [...req.headers.entries()].map(([key, value]) => [key, [value]]),
    ),
    queryStringParameters: Object.fromEntries(url.searchParams),
    multiValueQueryStringParameters: Object.fromEntries(
      [...url.searchParams.entries()].map(([key, value]) => [key, [value]]),
    ),
    pathParameters: ("pathParameters" in requestContextV1 &&
      requestContextV1?.pathParameters) ||
      null,
    stageVariables: ("stageVariables" in requestContextV1 &&
      requestContextV1?.stageVariables) ||
      null,
    body: bodyText,
    isBase64Encoded: false,
    requestContext: {
      accountId,
      apiId: requestContextV1?.apiId || Deno.env.get("AWS_API_GATEWAY_ID") ||
        "",
      authorizer: requestContextV1?.authorizer || null,
      protocol: getHeader(req, "x-forwarded-proto") || "https",
      resourceId: requestContextV1?.resourceId || "",
      resourcePath: requestContextV1?.resourcePath || url.pathname,
      httpMethod: req.method,
      requestId: requestContextV1?.requestId || crypto.randomUUID(),
      requestTime: requestContextV1?.requestTime || new Date().toISOString(),
      requestTimeEpoch: requestContextV1?.requestTimeEpoch || Date.now(),
      stage: requestContextV1?.stage ||
        Deno.env.get("AWS_LAMBDA_FUNCTION_STAGE") ||
        "prod",
      identity: {
        accessKey: requestContextV1?.identity?.accessKey ||
          Deno.env.get("AWS_ACCESS_KEY_ID") ||
          null,
        accountId: requestContextV1?.identity?.accountId || accountId || null,
        apiKey: requestContextV1?.identity?.apiKey ||
          getHeader(req, "x-api-key") ||
          null,
        apiKeyId: requestContextV1?.identity?.apiKeyId || null,
        caller: requestContextV1?.identity?.caller ||
          Deno.env.get("AWS_CALLER_ID") ||
          null,
        cognitoAuthenticationProvider:
          requestContextV1?.identity?.cognitoAuthenticationProvider ||
          getHeader(req, "x-amzn-cognito-authentication-provider") ||
          null,
        cognitoAuthenticationType:
          requestContextV1?.identity?.cognitoAuthenticationType ||
          getHeader(req, "x-amzn-cognito-authentication-type") ||
          null,
        cognitoIdentityId: requestContextV1?.identity?.cognitoIdentityId ||
          getHeader(req, "x-amzn-cognito-identity-id") ||
          null,
        cognitoIdentityPoolId:
          requestContextV1?.identity?.cognitoIdentityPoolId ||
          getHeader(req, "x-amzn-cognito-identity-pool-id") ||
          null,
        principalOrgId: requestContextV1?.identity?.principalOrgId ||
          getHeader(req, "x-amzn-principal-org-id") ||
          null,
        sourceIp: requestContextV1?.identity?.sourceIp ||
          getHeader(req, "x-forwarded-for")?.split(",")[0] ||
          getHeader(req, "x-real-ip") ||
          "0.0.0.0",
        user: requestContextV1?.identity?.user ||
          getHeader(req, "x-amzn-oidc-identity") ||
          getHeader(req, "x-amzn-oidc-data")?.split(".")[1] ||
          null,
        userAgent: requestContextV1?.identity?.userAgent ||
          getHeader(req, "user-agent") ||
          null,
        userArn: requestContextV1?.identity?.userArn ||
          getHeader(req, "x-amzn-oidc-identity-arn") ||
          getHeader(req, "x-amzn-iam-user-arn") ||
          null,
        clientCert: requestContextV1?.identity?.clientCert || {
          clientCertPem: getHeader(req, "x-amzn-client-cert-pem") || null,
          issuerDN: getHeader(req, "x-amzn-client-cert-issuer-dn") || null,
          serialNumber: getHeader(req, "x-amzn-client-cert-serial-number") ||
            null,
          subjectDN: getHeader(req, "x-amzn-client-cert-subject-dn") || null,
          validity: {
            notAfter: getHeader(req, "x-amzn-client-cert-not-after") || null,
            notBefore: getHeader(req, "x-amzn-client-cert-not-before") || null,
          },
        },
      },
      path: url.pathname,
      domainName: requestContextV1?.domainName ||
        getHeader(req, "host") ||
        getHeader(req, "x-forwarded-host") ||
        "",
      domainPrefix: requestContextV1?.domainPrefix ||
        getHeader(req, "host")?.split(".")[0] ||
        "",
      extendedRequestId: requestContextV1?.extendedRequestId ||
        crypto.randomUUID(),
      apiGateway: true,
    },
  } as APIGatewayProxyEvent;
};

const constructApiGatewayEvent = (
  req: Request,
  bodyText: string,
  url: URL,
  requestContext:
    | APIGatewayEventRequestContextV2
    | APIGatewayEventRequestContext
    | null,
): APIGatewayProxyEvent | APIGatewayProxyEventV2 => {
  return requestContext?.apiId !== undefined
    ? constructApiGatewayV2Event(
      req,
      bodyText,
      url,
      requestContext as APIGatewayEventRequestContextV2,
    )
    : constructApiGatewayV1Event(
      req,
      bodyText,
      url,
      requestContext as APIGatewayEventRequestContext,
    );
};

// Update StreamingResponse type to include base64 handling
export type StreamingResponse = {
  statusCode: number;
  body: ReadableStream | string;
  isBase64Encoded?: boolean;
  headers: Record<string, string>;
  contentType?: string; // Add optional content type for proper binary handling
}

// Update helper for binary content types to be more flexible
const isBinaryResponse = (contentType?: string): boolean => {
  if (!contentType) return false;
  
  // Normalize content type and get main type/subtype
  const [mainType, subType = ''] = contentType.toLowerCase().split('/');

  // Common binary main types
  const binaryMainTypes = new Set([
    'image',
    'audio',
    'video',
    'font',
    'application',
    'model',
    'chemical'
  ]);

  // If main type is known binary, return true
  if (binaryMainTypes.has(mainType)) {
    // Special case: some application subtypes are text-based
    if (mainType === 'application') {
      // Common text-based application subtypes
      const textSubtypes = new Set([
        'json',
        'ld+json',
        'xml',
        'yaml',
        'javascript',
        'ecmascript',
        'x-www-form-urlencoded',
        'graphql',
        'html',
        'xhtml',
        'x-sh',
        'x-csh',
        'x-httpd-php',
        'x-javascript',
        'x-perl',
        'x-python',
        'x-ruby',
        'x-latex',
        'x-tex',
        'x-markdown',
        'x-www-form-urlencoded',
        'soap+xml',
        'x-yaml',
        'x-toml'
      ]);
      
      return !textSubtypes.has(subType);
    }
    return true;
  }

  // Check for specific binary indicators in subtype
  const binaryIndicators = [
    'octet',
    'stream',
    'binary',
    'raw',
    'cbor',
    'msgpack',
    'protobuf',
    'bson',
    'x-binary',
    'x-mixed-binary',
    'vnd.ms-',
    'vnd.openxmlformats-',
    'x-bytecode',
    'x-object',
    'x-executable',
    'x-sharedlib',
    'x-deb',
    'x-rpm',
    'x-mach-binary',
    'x-archive',
    'x-compress',
    'x-compressed',
    'x-zip',
    'x-7z',
    'x-rar',
    'x-tar',
    'x-bzip',
    'x-gzip'
  ];

  // Check for vendor-specific binary formats
  if (subType.startsWith('vnd.')) {
    // Known vendor binary format families
    const binaryVendorPrefixes = [
      'vnd.ms-',
      'vnd.openxmlformats-',
      'vnd.oasis.',
      'vnd.adobe.',
      'vnd.apple.',
      'vnd.android.',
      'vnd.debian.',
      'vnd.sun.',
      'vnd.oracle.',
      'vnd.mozilla.'
    ];
    
    return binaryVendorPrefixes.some(prefix => subType.includes(prefix));
  }

  // Check for binary indicators in subtype
  return binaryIndicators.some(indicator => subType.includes(indicator));
};

// Helper to check if a content type is compressible
const isCompressibleResponse = (contentType?: string): boolean => {
  if (!contentType) return false;
  
  // Already compressed formats
  const nonCompressibleTypes = new Set([
    'image/jpeg',
    'image/jpg',
    'image/gif',
    'image/png',
    'image/webp',
    'image/avif',
    'audio/mp3',
    'audio/aac',
    'audio/mp4',
    'video/mp4',
    'video/mpeg',
    'application/zip',
    'application/x-zip-compressed',
    'application/x-7z-compressed',
    'application/x-rar-compressed',
    'application/gzip',
    'application/x-gzip',
    'application/x-bzip2',
    'application/x-brotli',
    'application/x-compress'
  ]);

  return !nonCompressibleTypes.has(contentType.toLowerCase());
};

// Update the streaming response handling in serveHttpLambda
const handleStreamingResponse = (result: StreamingResponse): Response => {
  const contentType = result.contentType || result.headers["Content-Type"] || "application/json";
  const baseHeaders = {
    "Content-Type": contentType,
    ...(result.headers || {}),
  };

  // For binary streams that need base64 encoding
  if (result.isBase64Encoded && isBinaryResponse(contentType)) {
    const transformStream = new TransformStream({
      transform(chunk: Uint8Array, controller) {
        const base64Chunk = btoa(String.fromCharCode(...chunk));
        controller.enqueue(new TextEncoder().encode(base64Chunk));
      },
    });

    // Apply compression if enabled and content is compressible
    const isCompressionEnabled = Deno.env.get("AWS_LWA_ENABLE_COMPRESSION") === "true";
    if (isCompressionEnabled && isCompressibleResponse(contentType)) {
      return new Response(
        (result.body as ReadableStream)
          .pipeThrough(transformStream)
          .pipeThrough(new CompressionStream("gzip")),
        {
          status: result.statusCode || 200,
          headers: {
            ...baseHeaders,
            "Content-Encoding": "gzip",
          },
        }
      );
    }

    return new Response(
      (result.body as ReadableStream).pipeThrough(transformStream),
      {
        status: result.statusCode || 200,
        headers: baseHeaders,
      }
    );
  }

  // Regular streaming response
  const stream = typeof result.body === 'string'
    ? new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(result.body as string));
          controller.close();
        }
      })
    : result.body as ReadableStream;

  // Apply compression if enabled and content is compressible
  const isCompressionEnabled = Deno.env.get("AWS_LWA_ENABLE_COMPRESSION") === "true";
  if (isCompressionEnabled && isCompressibleResponse(contentType)) {
    return new Response(
      stream.pipeThrough(new CompressionStream("gzip")),
      {
        status: result.statusCode || 200,
        headers: {
          ...baseHeaders,
          "Content-Encoding": "gzip",
        },
      }
    );
  }

  return new Response(stream, {
    status: result.statusCode || 200,
    headers: baseHeaders,
  });
};

// Add streaming event types
export type StreamingAPIGatewayProxyEvent = Omit<APIGatewayProxyEvent, 'body'> & {
  body: ReadableStream;
  isStreaming: true;
}

export type StreamingAPIGatewayProxyEventV2 = Omit<APIGatewayProxyEventV2, 'body'> & {
  body: ReadableStream;
  isStreaming: true;
}

// Separate the handler types
export type StandardHttpHandler = (
  event: APIGatewayProxyEvent | APIGatewayProxyEventV2,
  context: Context,
) => Promise<APIGatewayProxyResult | APIGatewayProxyResultV2>;

export type StreamingHttpHandler = (
  event: StreamingAPIGatewayProxyEvent | StreamingAPIGatewayProxyEventV2,
  context: Context,
) => Promise<StreamingResponse>;

// Update the handler type to be more specific
export type HttpHandler = StandardHttpHandler | StreamingHttpHandler;

// Update serveHttpLambda signature to be more explicit
export const serveHttpLambda = (
  handler: HttpHandler,
  logger?: Logger,
): (req: Request) => Promise<Response> => {
  return async (req: Request): Promise<Response> => {
    const isResponseStreaming = Deno.env.get("AWS_LWA_INVOKE_MODE") === "response_stream";

    try {
      logger?.debug("Handling HTTP Lambda request", {
        method: req.method,
        url: req.url,
        headers: Object.fromEntries(req.headers),
      });

      // Handle preflight CORS requests
      if (req.method === "OPTIONS") {
        logger?.debug("Handling CORS preflight request");
        return new Response(null, {
          status: 204,
          headers: {
            ...createCorsHeaders(true),
            "Content-Length": "0",
            "Cache-Control": "max-age=86400",
          },
        });
      }

      const requestContext = parseRequestContext(req) || null;
      const context = parseContext(req) || ({} as Context);
      const url = new URL(req.url);

      // Improve streaming request handling
      if (isResponseStreaming) {
        // Only require body for POST/PUT/PATCH methods
        const requiresBody = ['POST', 'PUT', 'PATCH'].includes(req.method);
        if (requiresBody && !req.body) {
          throw new Error("Streaming mode requires a request body for POST/PUT/PATCH requests");
        }

        if (!isStreamingHandler(handler)) {
          throw new Error("Streaming mode requires a streaming handler");
        }

        const streamingEvent = {
          ...constructApiGatewayEvent(req, "", url, requestContext),
          body: req.body || new ReadableStream(), // Provide empty stream for GET requests
          isStreaming: true as const,
        } as StreamingAPIGatewayProxyEvent | StreamingAPIGatewayProxyEventV2;

        try {
          const result = await handler(streamingEvent, context);
          return handleStreamingResponse(result);
        } catch (streamError) {
          // Handle streaming-specific errors
          logger?.error("Streaming handler error", {
            error: streamError instanceof Error ? streamError : new Error(String(streamError)),
            path: new URL(req.url).pathname,
            method: req.method,
          });

          // Return error response to client
          return new Response(
            JSON.stringify({
              message: "Streaming Error",
              error: isNodeDevelopment ? 
                (streamError instanceof Error ? streamError.message : String(streamError)) 
                : "Internal Server Error"
            }),
            {
              status: 500,
              headers: {
                "Content-Type": "application/json",
                ...createCorsHeaders(Boolean(requestContext))
              }
            }
          );
        }
      }

      // Handle regular request with improved type safety
      if (isStreamingHandler(handler)) {
        throw new Error("Non-streaming mode requires a standard handler");
      }

      const bodyText = await getRequestBody(req);
      const event = constructApiGatewayEvent(req, bodyText, url, requestContext);
      const result = await handler(event, context);
      
      const hasRequestContext = Boolean(getHeader(req, "x-amzn-request-context"));
      const baseHeaders: Record<string, string> = {
        "Content-Type": "application/json",
        "X-Content-Type-Options": "nosniff",
        ...createCorsHeaders(hasRequestContext),
      };

      // Handle streaming response
      if (typeof result === 'object' && result !== null &&
          'body' in result && result.body && 
          typeof result.body === 'object' && 
          'getReader' in result.body) {
        return handleStreamingResponse(result as StreamingResponse);
      }

      // Handle regular response
      const responseBody = JSON.stringify(result);
      const isCompressionEnabled = Deno.env.get("AWS_LWA_ENABLE_COMPRESSION") === "true";

      if (isCompressionEnabled) {
        const compressed = await compressResponse(responseBody);
        return new Response(compressed, {
          headers: {
            ...baseHeaders,
            "Content-Encoding": "gzip",
          },
        });
      }

      return new Response(responseBody, { headers: baseHeaders });
    } catch (error: unknown) {
      logger?.error("HTTP handler error", {
        error: error instanceof Error ? error : new Error(String(error)),
        path: new URL(req.url).pathname,
        method: req.method,
        message: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
        timestamp: new Date().toISOString(),
      });

      const hasRequestContext = Boolean(
        getHeader(req, "x-amzn-request-context"),
      );

      const errorResponse = {
        message: "Internal Server Error",
        ...(isNodeDevelopment && {
          error: error instanceof Error ? error.message : String(error),
        }),
      };

      const baseErrorHeaders = {
        "Content-Type": "application/json",
        ...createCorsHeaders(hasRequestContext),
      };

      if (isResponseStreaming) {
        const stream = new TransformStream();
        const writer = stream.writable.getWriter();
        
        const encoder = new TextEncoder();
        await writer.write(encoder.encode(JSON.stringify(errorResponse)));
        await writer.close();

        return new Response(stream.readable, {
          status: 500,
          headers: {
            ...baseErrorHeaders,
            "Transfer-Encoding": "chunked",
          },
        });
      }

      return new Response(JSON.stringify(errorResponse), {
        status: 500,
        headers: baseErrorHeaders,
      });
    }
  };
};

// Add type guard for streaming handler
const isStreamingHandler = (
  _handler: HttpHandler,
): _handler is StreamingHttpHandler => {
  return Deno.env.get("AWS_LWA_INVOKE_MODE") === "response_stream";
};

// Update LambdaServerOptions to use the new HttpHandler type
type LambdaServerOptions = {
  // deno-lint-ignore no-explicit-any
  eventHandler?: <T = any, R = any>(event: T, context: Context) => Promise<R>;
  httpHandler?: HttpHandler;
  healthHandler?: (req: Request) => Response | Promise<Response>;
  logger?: Logger;
  onShutdown?: () => Promise<void> | void;
};

// Helper function to get request body (move existing body handling logic here)
const getRequestBody = async (req: Request): Promise<string> => {
  const contentType = req.headers.get("content-type")?.toLowerCase() || "application/json";
  
  if (contentType.includes("multipart/form-data")) {
    const formData = await req.formData();
    const formDataObj = await processFormData(formData);
    return JSON.stringify(formDataObj);
  } else if (contentType.includes("application/x-www-form-urlencoded")) {
    const formData = await req.formData();
    return JSON.stringify(Object.fromEntries(formData));
  } else if (isBinaryContentType(contentType)) {
    const buffer = await req.arrayBuffer();
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
  } else {
    return await req.text();
  }
};

// Helper functions
const isBinaryContentType = (contentType: string): boolean => {
  return contentType.startsWith("image/") || 
         contentType.startsWith("audio/") || 
         contentType.startsWith("video/") || 
         contentType.startsWith("application/octet-stream");
};

const processFormData = async (formData: FormData): Promise<Record<string, unknown>> => {
  const formDataObj: Record<string, unknown> = {};
  
  for (const [key, value] of formData.entries()) {
    if (value instanceof File || (typeof value === "object" && value !== null && "arrayBuffer" in value)) {
      const buffer = await (value instanceof File ? value : value as Blob).arrayBuffer();
      const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
      
      formDataObj[key] = {
        type: value instanceof File ? "file" : "blob",
        ...(value instanceof File && {
          name: value.name,
          lastModified: value.lastModified,
        }),
        mimeType: value instanceof File ? value.type : (value as Blob).type,
        size: value instanceof File ? value.size : (value as Blob).size,
        data: base64
      };
    } else {
      formDataObj[key] = String(value);
    }
  }
  
  return formDataObj;
};

// Update serveEventLambda to handle event source context
export const serveEventLambda = (
  // deno-lint-ignore no-explicit-any
  handler: (event: any, context: Context) => Promise<any>,
  logger?: Logger,
): (req: Request) => Promise<Response> => {
  return async (req: Request): Promise<Response> => {
    try {
      logger?.debug("Handling event Lambda request", {
        method: req.method,
        url: req.url,
      });

      if (req.method !== "POST") {
        logger?.warn("Method not allowed for event handler", {
          path: new URL(req.url).pathname,
          method: req.method,
        });
        return new Response(JSON.stringify({ message: "Method Not Allowed" }), {
          status: 405,
        });
      }

      logger?.debug("Reading event payload");
      const eventInput = await req.text().catch(() => null);
      let event = {};
      let error: Error | null = null;
      try {
        event = JSON.parse(eventInput || '');
      } catch (e) {
        if (!(e instanceof Error)) throw e;
        error = e;
      }

      if (error) {
        logger?.error("Malformed JSON in Lambda event", {
          path: new URL(req.url).pathname,
          rawInput: eventInput,
          error: error instanceof Error ? error.message : String(error),
        });
        return new Response(
          JSON.stringify({ message: `Invalid JSON payload: ${eventInput}` }),
          {
            status: 400,
            headers: { "Content-Type": "application/json" },
          },
        );
      }

      if (typeof event !== "object") {
        throw new Error(`Lambda event is not an object: ${event}`);
      }

      logger?.debug("Parsing Lambda context");
      const context = parseContext(req) || ({} as Context);

      logger?.debug("Invoking event handler");
      const result = await handler(event, context);
      logger?.debug("Event handler completed successfully", {
        resultType: typeof result,
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
        timestamp: new Date().toISOString(),
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
        },
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
}: LambdaServerOptions) =>
() => {
  logger?.info("Initializing Lambda server (invoke mode: " + Deno.env.get("AWS_LWA_INVOKE_MODE") + ")", {
    hasEventHandler: !!eventHandler,
    hasHttpHandler: !!httpHandler,
    hasCustomHealthHandler: healthHandler !== defaultHealthHandler,
    hasShutdownHandler: !!onShutdown,
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
          stack: error instanceof Error ? error.stack : undefined,
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
        },
      );
    },
  };

  // Get environment variables with fallbacks
  const mainPort = (() => {
    const port = parseInt(
      Deno.env.get("AWS_LWA_PORT") ?? Deno.env.get("PORT") ?? "8080",
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
        String(mainPort),
    );
    if (port === 9001 || port === 3000) {
      throw new Error(`Port ${port} is reserved and cannot be used`);
    }
    return port;
  })();

  const readinessPath = Deno.env.get("AWS_LWA_READINESS_CHECK_PATH") ||
    Deno.env.get("READINESS_CHECK_PATH") ||
    "/";

  // Update handler to properly await all async operations
  const mainHandler = async (req: Request): Promise<Response> => {
    const pathname = new URL(req.url).pathname;
    const eventsPath = Deno.env.get("AWS_LWA_PASS_THROUGH_PATH") || "/events";

    logger?.debug("Received request", {
      method: req.method,
      path: pathname,
      headers: Object.fromEntries(req.headers),
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
        if (
          Deno.env.get("AWS_LWA_INVOKE_MODE") === "response_stream" &&
          eventHandler
        ) {
          return new Response(
            JSON.stringify({
              error:
                "Response streaming mode is not supported when using an event handler",
            }),
            {
              status: 400,
              headers: {
                "Content-Type": "application/json",
              },
            },
          );
        }
  
        logger?.debug("Routing to event handler");
        if (!eventHandler) {
          logger?.warn("Event handler not configured");
          return new Response("Handler not found", { status: 404 });
        }
        return await serveEventLambda(eventHandler, logger)(req);
      } else if (pathname === eventsPath && req.method !== "POST") {
        logger?.warn(
          `Method ${req.method} not allowed for events path ${eventsPath}`,
          {
            path: pathname,
            method: req.method,
          },
        );
        return new Response("Method Not Allowed", { status: 405 });
      }

      // Handle all other paths with HTTP handler
      if (httpHandler) {
        logger?.debug("Routing to HTTP handler");
        return await serveHttpLambda(httpHandler, logger)(req);
      }

      // No handler configured
      logger?.warn("No handler configured for request", {
        path: pathname,
        method: req.method,
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
        timestamp: new Date().toISOString(),
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
        },
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
          message: `Application listening on ${addr.hostname}:${addr.port}`,
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
            requestUrl: req.url,
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
            message:
              `Health check listening on ${addr.hostname}:${addr.port}${readinessPath}`,
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
