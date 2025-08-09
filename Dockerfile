# Multi-stage build for smaller final image
FROM rust:1.77 as build

# Set environment variables for cargo
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

# Set the working directory
WORKDIR /app

# Copy the simplified Cargo files for dependency building
COPY Cargo.simple.toml ./Cargo.toml

# Generate a new Cargo.lock compatible with this Rust version
RUN cargo generate-lockfile

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (this will be cached if Cargo files don't change)
RUN cargo build --release --bin server
RUN rm src/main.rs

# Copy the source code
COPY src/ src/
COPY examples/ examples/

# Build the actual application
RUN cargo build --release --bin server

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create a non-root user
RUN useradd -r -s /bin/false elhaiba

# Set the working directory
WORKDIR /app

# Copy the binary from the build stage
COPY --from=build /app/target/release/server /app/server

# Create directories for logs (if needed)
RUN mkdir -p /app/logs && chown elhaiba:elhaiba /app/logs

# Change ownership of the app directory
RUN chown -R elhaiba:elhaiba /app

# Switch to non-root user
USER elhaiba

# Expose the port (adjust if your app uses a different port)
EXPOSE 4000

# Set environment variables
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:4000/health || exit 1

# Run the application
CMD ["./server"]
