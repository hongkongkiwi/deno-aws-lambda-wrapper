# Set up the base image
ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG LAMBDA_ADAPTER_ARCH
ARG LAMBDA_ADAPTER_VERSION=0.8.4
ARG DENO_VERSION=2.0.6
ARG COMPILE_OS_FLAVOR=debian
ARG RUNTIME_OS_FLAVOR=debian
ARG RUNTIME_OS_VERSION=bookworm-slim

FROM --platform=${BUILDPLATFORM} public.ecr.aws/awsguru/aws-lambda-adapter:${LAMBDA_ADAPTER_VERSION}-${LAMBDA_ADAPTER_ARCH} AS aws-lambda-adapter

# Build stage
FROM --platform=${BUILDPLATFORM} denoland/deno:${COMPILE_OS_FLAVOR}-${DENO_VERSION} AS builder

ARG TMPDIR=/tmp
ARG TASK_DIR=/var/task
ARG DENO_DIR=/var/deno_dir
# Build stage
WORKDIR "/build"

# Copy the rest of the source code
COPY ./ .

RUN deno cache \
    --allow-scripts=npm:aws-sdk \
    ./test_handler.ts

# Compile the application with specific permissions
RUN deno compile \
    --output=dist/app \
    --cached-only \
    --no-prompt \
    --allow-read=${TASK_DIR},${DENO_DIR},${TMPDIR},/root/.aws \
    --allow-write=${TASK_DIR},${DENO_DIR},${TMPDIR} \
    --allow-net \
    --allow-env \
    --allow-sys \
    --allow-ffi \
    ./test_handler.ts

# Runtime stage
FROM --platform=${BUILDPLATFORM} ${RUNTIME_OS_FLAVOR}:${RUNTIME_OS_VERSION} AS runtime
# Copy Lambda adapter
COPY --from=aws-lambda-adapter /lambda-adapter /opt/extensions/lambda-adapter

ARG PORT=8080
ARG TMPDIR=/tmp
ARG TASK_DIR=/var/task
ARG DENO_DIR=/var/deno_dir
ARG DENO_ENV=production

# Create necessary directories and set workdir in one layer
RUN mkdir -p $TASK_DIR $DENO_DIR

WORKDIR $TASK_DIR

# Copy the compiled binary from builder stage
COPY --from=builder /build/dist/app ./app

# Set up environment
ENV PORT=$PORT \
    TASK_DIR=$TASK_DIR \
    DENO_DIR=$DENO_DIR \
    DENO_ENV=$DENO_ENV \
    NODE_ENV=$DENO_ENV \
    TMPDIR=$TMPDIR \
    IS_DOCKER=true
EXPOSE $PORT

# Simple run command
CMD ["./app"]
