import { startLambdaServer } from "./mod.ts";
import { Logger } from "npm:@aws-lambda-powertools/logger";
import type {
  StreamingHttpHandler,
  StreamingResponse,
  StreamingAPIGatewayProxyEvent,
  StreamingAPIGatewayProxyEventV2,
} from "./mod.ts";
import type {
  Context,
} from "npm:@types/aws-lambda";

Deno.env.set("POWERTOOLS_DEV", "true");
Deno.env.set("LOG_LEVEL", "DEBUG");
Deno.env.set("AWS_LWA_INVOKE_MODE", "response_stream");
Deno.env.set("DENO_ENV", "development");

const logger = new Logger({
  serviceName: "lambda-server",
  logLevel: "DEBUG",
});

// deno-lint-ignore require-await
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

// deno-lint-ignore require-await
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

// deno-lint-ignore require-await
const streamingHttpHandler = async (
  event: StreamingAPIGatewayProxyEvent | StreamingAPIGatewayProxyEventV2,
  context: Context
): Promise<StreamingResponse> => {
  try {
    logger.info("Received streaming HTTP request", { event, context });
    const method =
      "httpMethod" in event
        ? event.httpMethod
        : event.requestContext.http.method;
    const path = "path" in event ? event.path : event.requestContext.http.path;

    // Create a TransformStream for streaming data
    const { readable, writable } = new TransformStream();
    const writer = writable.getWriter();

    // Start async writing process
    (async () => {
      try {
        for (let i = 0; i < 5; i++) {
          const chunk = {
            message: `Streaming chunk ${i + 1}`,
            path,
            method,
            requestId: context.awsRequestId,
            timestamp: new Date().toISOString(),
          };

          await writer.write(
            new TextEncoder().encode(JSON.stringify(chunk) + "\n")
          );
          await new Promise((resolve) => setTimeout(resolve, 1000)); // Simulate delay
        }
      } finally {
        await writer.close();
      }
    })();

    return {
      statusCode: 200,
      body: readable,
      headers: {
        "Content-Type": "application/x-ndjson",
        "Transfer-Encoding": "chunked",
      },
    };
  } catch (error) {
    logger.error("Error in streaming HTTP handler", { error });
    throw error;
  }
};

// Binary streaming example (e.g., for image streaming)
// deno-lint-ignore require-await
const binaryStreamingHandler = async (
  event: StreamingAPIGatewayProxyEvent | StreamingAPIGatewayProxyEventV2,
  context: Context
): Promise<StreamingResponse> => {
  try {
    logger.info("Received binary streaming request", { event, context });

    const stream = new ReadableStream({
      start: async (controller) => {
        const chunk = new Uint8Array([0xff, 0xd8, 0xff, 0xe0]);
        controller.enqueue(chunk);

        for (let i = 0; i < 3; i++) {
          await new Promise((resolve) => setTimeout(resolve, 500));
          const dataChunk = new Uint8Array(1024).fill(i);
          controller.enqueue(dataChunk);
        }

        controller.close();
      },
    });

    return {
      statusCode: 200,
      body: stream,
      isBase64Encoded: true,
      contentType: "image/jpeg",
      headers: {
        "Content-Type": "image/jpeg",
        "Transfer-Encoding": "chunked",
      },
    };
  } catch (error) {
    logger.error("Error in binary streaming handler", { error });
    throw error;
  }
};

// deno-lint-ignore require-await
const streamingTestHandler: StreamingHttpHandler = async (
  event: StreamingAPIGatewayProxyEvent | StreamingAPIGatewayProxyEventV2,
  context: Context
): Promise<StreamingResponse> => {
  const path = "path" in event ? event.path : event.requestContext.http.path;

  // Route to appropriate handler based on path
  if (path === "/stream/text") return streamingHttpHandler(event, context);
  if (path === "/stream/binary") return binaryStreamingHandler(event, context);
  if (path === "/stream/error") throw new Error("Simulated streaming error");

  // Default JSON streaming response
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();

  (async () => {
    try {
      await writer.write(
        new TextEncoder().encode(
          JSON.stringify({
            message: "Default streaming response",
            path,
            timestamp: new Date().toISOString(),
          }) + "\n"
        )
      );
    } finally {
      await writer.close();
    }
  })();

  return {
    statusCode: 200,
    body: readable,
    headers: {
      "Content-Type": "application/x-ndjson",
      "Transfer-Encoding": "chunked",
    },
  };
};

startLambdaServer({
  httpHandler: streamingTestHandler,
  eventHandler,
  healthHandler,
  logger: logger as unknown as Logger,
})();

// Handle Deno signals
let isShuttingDown = false;

const shutdown = (): void => {
  if (isShuttingDown) return;
  isShuttingDown = true;
  Deno.exit(0);
};

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  Deno.addSignalListener(signal, shutdown);
}

// Keep the process alive
await new Promise(() => {});
