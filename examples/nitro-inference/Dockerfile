# Stage 1: Build the enclave binary
FROM rust:1.93-bookworm AS builder
RUN apt-get update && apt-get install -y libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release --bin enclave-server \
    --manifest-path examples/nitro-inference/Cargo.toml \
    --no-default-features --features vsock-nitro

# Stage 2: Runtime image (minimal)
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

# Copy binary
COPY --from=builder /build/target/release/enclave-server /app/enclave-server

# Copy model files (pre-downloaded by build.sh)
COPY examples/nitro-inference/model/ /model/

# Copy init script
COPY examples/nitro-inference/init.sh /app/init.sh
RUN chmod +x /app/init.sh

ENTRYPOINT ["/app/init.sh"]
