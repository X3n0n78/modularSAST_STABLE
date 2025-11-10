# ModularSAST Docker Image
# Multi-stage build for optimized image size

FROM ubuntu:22.04 as builder

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    golang-go \
    g++ \
    libclang-18-dev \
    llvm-18-dev \
    python3 \
    python3-pip \
    python3-yaml \
    nodejs \
    npm \
    build-essential \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy source code
COPY . /build/

# Build C++ analyzer
WORKDIR /build/analyzers/cpp
RUN g++ main.cpp -o cpp_analyzer -I/usr/lib/llvm-18/include -L/usr/lib/llvm-18/lib -lclang -Wl,-rpath,/usr/lib/llvm-18/lib

# Build Go analyzer
WORKDIR /build/analyzers/go
RUN go mod init goanalyzer || true
RUN go build -o go_analyzer main.go

# Runtime stage
FROM ubuntu:22.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    golang-go \
    python3 \
    python3-yaml \
    nodejs \
    libclang-18 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy built analyzers from builder stage
COPY --from=builder /build/analyzers /app/analyzers
COPY --from=builder /build/rules /app/rules
COPY --from=builder /build/core /app/core
COPY --from=builder /build/go.mod /app/go.mod
COPY --from=builder /build/go.sum /app/go.sum
COPY --from=builder /build/.modularsast.yaml /app/.modularsast.yaml

# Make scripts executable
RUN chmod +x /app/analyzers/python/main.py || true
RUN chmod +x /app/analyzers/regex/main.py || true
RUN chmod +x /app/analyzers/javascript/main.js || true

# Set working directory for scans
WORKDIR /scan

# Set the entrypoint to run ModularSAST
ENTRYPOINT ["go", "run", "/app/core/main.go"]

# Default command (can be overridden)
CMD ["--path=/scan"]
