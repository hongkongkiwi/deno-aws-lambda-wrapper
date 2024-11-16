# AWS Lambda Adapter for Deno

A lightweight wrapper for AWS Lambda Adapter optimized for Deno runtime environments.

## Features

- 🦕 First-class Deno support with AWS Lambda Powertools
- ⚡️ AWS Lambda integration made simple
- 🔄 Seamless request/response handling for API Gateway v1/v2
- 🛡️ Type-safe with TypeScript
- 🚀 Minimal overhead
- 📦 Zero external dependencies
- 💨 Fast cold starts
- 🔍 Easy debugging with environment variables

## Overview

This wrapper simplifies the process of running Deno applications on AWS Lambda using the AWS Lambda Adapter. It provides a clean interface to handle HTTP requests, events, and health checks while maintaining Deno's security and performance benefits.

## Installation

To use this adapter in your Deno project, import the required dependencies:

```ts
import { startLambdaServer } from "./mod.ts";
import { Logger } from "@aws-lambda-powertools/logger";
import type {
  Context,
  APIGatewayProxyEvent,
  APIGatewayProxyEventV2,
  APIGatewayProxyResult,
  APIGatewayProxyResultV2,
} from "npm:@types/aws-lambda";
```

## Quick Start

The adapter provides three main handler types that can be used together:

### HTTP Handler

For handling API Gateway requests:

```ts
const httpHandler = async (
  event: APIGatewayProxyEvent | APIGatewayProxyEventV2,
  context: Context
): Promise<APIGatewayProxyResult | APIGatewayProxyResultV2> => {
  try {
    logger.info("Received HTTP request", { event, context });
    const method = 'httpMethod' in event ? event.httpMethod : event.requestContext.http.method;
    const path = 'path' in event ? event.path : event.requestContext.http.path;
    
    return {
      statusCode: 200,
      body: JSON.stringify({
        message: "Hello from HTTP handler!",
        path,
        method,
        requestId: context.awsRequestId,
      }),
      headers: {
        "Content-Type": "application/json",
      },
    };
  } catch (error) {
    logger.error("Error in HTTP handler", { error });
    throw error;
  }
};
```

### Event Handler

For processing AWS events:

```ts
const eventHandler = async <T = unknown, R = unknown>(
  event: T,
  context: Context
): Promise<R> => {
  try {
    logger.info("Received event", { event, context });
    return {
      message: "Hello from event handler!",
      event,
      requestId: context.awsRequestId,
    } as R;
  } catch (error) {
    logger.error("Error in event handler", { error });
    throw error;
  }
};
```

### Health Check Handler

A health check handler is required by AWS Lambda Adapter to ensure that your function is healthy and ready to receive requests. A default handler is provided for convenience.

If you want to implement a custom health check handler, you can do so by providing a custom function. For example:

```ts
const healthHandler = async (req: Request): Promise<Response> => {
  try {
    logger.info("Health check requested", { path: new URL(req.url).pathname });
    return new Response(
      JSON.stringify({
        status: "healthy",
        timestamp: new Date().toISOString(),
      }),
      {
        headers: { "Content-Type": "application/json" },
      }
    );
  } catch (error) {
    logger.error("Error in health check handler", { error });
    throw error;
  }
};
```

## Server Setup

Initialize the Lambda server with all handlers:

```ts
const server = startLambdaServer({
  httpHandler,
  eventHandler,
  healthHandler,
  logger,
})();
```

## Graceful Shutdown

Handle Deno signals for clean shutdown:

```ts
let isShuttingDown = false;

const shutdown = () => {
  if (isShuttingDown) return;
  isShuttingDown = true;
  Deno.exit(0);
};

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  Deno.addSignalListener(signal, shutdown);
}
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

MIT License - see LICENSE file for details
