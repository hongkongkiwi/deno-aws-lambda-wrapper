import { startLambdaServer } from "./mod.ts";
import { Logger } from "@aws-lambda-powertools/logger";
import type {
  Context,
  APIGatewayProxyEvent,
  APIGatewayProxyEventV2,
  APIGatewayProxyResult,
  APIGatewayProxyResultV2,
} from "npm:@types/aws-lambda";

Deno.env.set("POWERTOOLS_DEV", "true");
Deno.env.set("LOG_LEVEL", "DEBUG");

const logger = new Logger({ serviceName: "lambda-server" });

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

const server = startLambdaServer({
  httpHandler,
  eventHandler,
  healthHandler,
  logger,
})();

// Handle Deno signals
let isShuttingDown = false;

const shutdown = () => {
  if (isShuttingDown) return;
  isShuttingDown = true;
  
  // Force exit without any logging
  Deno.exit(0);
};

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  Deno.addSignalListener(signal, shutdown);
}

// Keep the process alive
await new Promise(() => {});
