# AWS Lambda Adapter for Deno

A lightweight wrapper for AWS Lambda Adapter optimized for Deno runtime environments.

## Features

- 🦕 First-class Deno support
- ⚡️ AWS Lambda integration made simple
- 🔄 Seamless request/response handling
- 🛡️ Type-safe with TypeScript
- 🚀 Minimal overhead
- 📦 Zero external dependencies
- 💨 Fast cold starts
- 🔍 Easy debugging

## Overview

This wrapper simplifies the process of running Deno applications on AWS Lambda using the AWS Lambda Adapter. It provides a clean interface to handle HTTP requests and responses while maintaining Deno's security and performance benefits.

## Installation

To use this adapter in your Deno project, you can import it directly from the URL:

\```ts
import { createHttpHandler, createEventHandler, createHealthcheckHandler } from "https://deno.land/x/aws_lambda_adapter/mod.ts";
\```

You can also find example test utilities in test_handler.ts.

## Quick Start

The adapter provides three main handler types:

### HTTP Handler

For web applications and APIs:

\```ts
const handler = createHttpHandler({
  async fetch(request) {
    return new Response("Hello from Deno on AWS Lambda!");
  },
  healthcheck: async () => {
    return new Response("OK", { status: 200 });
  }
});

export { handler };
\```

### Event Handler

For processing AWS events (S3, SQS, etc.):

\```ts
const handler = createEventHandler({
  async handle(event, context) {
    console.log("Processing event:", event);
    return {
      statusCode: 200,
      body: "Event processed successfully"
    };
  },
  healthcheck: async () => {
    return { status: "healthy" };
  }
});

export { handler };
\```

### Healthcheck Handler

For dedicated health monitoring endpoints:

\```ts
const handler = createHealthcheckHandler({
  async check() {
    // Perform health checks
    return {
      status: "healthy",
      checks: {
        database: "ok",
        cache: "ok",
        externalApi: "ok"
      }
    };
  }
});
\```

## API Reference

### createHttpHandler(options)

Creates an HTTP-focused Lambda handler with the following options:

- `fetch`: Required. Function handling HTTP requests
- `healthcheck`: Optional. Health check endpoint handler
- `onError`: Optional. Custom error handler
- `logger`: Optional. Custom logging implementation

### createEventHandler(options)

Creates an event-processing Lambda handler:

- `handle`: Required. Function processing AWS events
- `healthcheck`: Optional. Health check implementation
- `onError`: Optional. Custom error handler
- `logger`: Optional. Custom logging implementation

### createHealthcheckHandler(options)

Creates a dedicated health check handler:

- `check`: Required. Function performing health checks
- `onError`: Optional. Custom error handler
- `logger`: Optional. Custom logging implementation

## Handler Interfaces

\```ts
interface HttpHandlerOptions {
  fetch: (request: Request) => Promise<Response>;
  healthcheck?: () => Promise<Response>;
  onError?: (error: Error) => Response;
  logger?: Logger;
}

interface EventHandlerOptions<T = any> {
  handle: (event: T, context: Context) => Promise<any>;
  healthcheck?: () => Promise<any>;
  onError?: (error: Error) => any;
  logger?: Logger;
}

interface HealthcheckHandlerOptions {
  check: () => Promise<any>;
  onError?: (error: Error) => any;
  logger?: Logger;
}
\```

## Health Checks

Implement health checks for monitoring and AWS ALB integration:

\```ts
const handler = createHttpHandler({
  fetch: async (request) => {
    // Main request handling
  },
  healthcheck: async () => {
    // Check database connection
    await db.ping();
    // Check external services
    await checkExternalServices();
    
    return new Response("Healthy", { status: 200 });
  }
});
\```

## Environment Variables

- `LAMBDA_TASK_ROOT`: Set by AWS Lambda
- `AWS_LAMBDA_RUNTIME_API`: Set by AWS Lambda
- `DEBUG`: Enable debug logging (optional)

## Deployment

1. Build your Deno application
2. Package it with required permissions
3. Deploy to AWS Lambda using the Deno runtime

Example deployment using Terraform:

\```hcl
resource "aws_lambda_function" "deno_app" {
  filename         = "function.zip"
  handler          = "handler.handler"
  runtime          = "provided.al2"
  function_name    = "deno-app"
  role            = aws_iam_role.lambda_role.arn
  
  environment {
    variables = {
      DENO_DEPLOYMENT = "production"
    }
  }
}
\```

## Error Handling

Custom error handling for each handler type:

\```ts
// HTTP Handler
const httpHandler = createHttpHandler({
  fetch: async (request) => {
    // Your request handling logic
  },
  onError: (error) => {
    console.error("HTTP error:", error);
    return new Response("Internal Server Error", { status: 500 });
  }
});

// Event Handler
const eventHandler = createEventHandler({
  handle: async (event) => {
    // Your event handling logic
  },
  onError: (error) => {
    console.error("Event processing error:", error);
    return { statusCode: 500, body: "Processing failed" };
  }
});
\```

## Logging

Built-in logging support with customization options:

\```ts
const handler = createHttpHandler({
  fetch: async (request) => {
    // Your request handling logic
  },
  logger: {
    debug: console.debug,
    info: console.info,
    warn: console.warn,
    error: console.error
  }
});
\```

## Examples

### HTTP API Server

\```ts
const handler = createHttpHandler({
  async fetch(request) {
    const { pathname } = new URL(request.url);
    
    switch (pathname) {
      case "/":
        return new Response("Welcome!");
      case "/api":
        return Response.json({ message: "API endpoint" });
      default:
        return new Response("Not Found", { status: 404 });
    }
  },
  healthcheck: async () => {
    return new Response("OK", { status: 200 });
  }
});
\```

### S3 Event Processor

\```ts
const handler = createEventHandler({
  async handle(event) {
    for (const record of event.Records) {
      if (record.eventName === "ObjectCreated:Put") {
        await processS3Object(record.s3);
      }
    }
    return { processed: event.Records.length };
  },
  healthcheck: async () => {
    return { status: "healthy", timestamp: Date.now() };
  }
});
\```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

MIT License - see LICENSE file for details

## Support

- GitHub Issues: [Report a bug](https://github.com/your-repo/issues)
- Discord: [Join our community](https://discord.gg/your-server)
- Twitter: [@YourHandle](https://twitter.com/your-handle)

## Acknowledgments

- AWS Lambda team
- Deno community
- Contributors
