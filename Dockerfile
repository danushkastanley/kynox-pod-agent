# Multi-stage Dockerfile to build the eBPF RASP agent on Linux

# Builder stage
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    build-essential \
    autoconf \
    autopoint \
    automake \
    bison \
    libc6-dev \
    clang-14 \
    llvm-14 \
    libelf-dev \
    libbpf-dev \
    libtool \
    pkg-config \
    linux-headers-generic \
    linux-libc-dev \
    git \
    gettext \
    flex \
    gawk \
    linux-tools-generic \
    protobuf-compiler \
    libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*

# Set up clang and llvm-strip
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 100 && \
    update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-14 100

# Install Rust
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable && \
    . $CARGO_HOME/env && \
    rustup component add rustfmt

# Set up kernel headers
RUN ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm && \
    ln -sf /usr/include/linux /usr/include/linux && \
    ln -sf /usr/lib/x86_64-linux-gnu/libbpf.so /usr/lib/libbpf.so

WORKDIR /workspace

# Copy dependency files first for better caching
COPY ./Cargo.toml ./Cargo.lock /workspace/
COPY ./agent/Cargo.toml /workspace/agent/
COPY ./agent-core/Cargo.toml /workspace/agent-core/

# Copy protobuf definition
COPY ./telemetry.proto /workspace/

# Create minimal src files to build dependencies
RUN mkdir -p agent/src agent-core/src && \
    echo "fn main() {}" > agent/src/main.rs && \
    echo "pub fn dummy() {}" > agent-core/src/lib.rs

# Fetch dependencies
RUN cargo fetch --locked

# Copy and build the eBPF core independently so application-only changes reuse it.
COPY ./agent-core/build.rs ./agent-core/
COPY ./agent-core/src/ ./agent-core/src/
COPY ./agent-core/bpf/ ./agent-core/bpf/

# Set LIBBPF path and build BPF code
ENV LIBBPF_PATH=/usr/lib/x86_64-linux-gnu \
    BPF_CLANG=clang-14 \
    LIBELF_INCLUDE_DIR=/usr/include \
    LIBBPF_INCLUDE_DIR=/usr/include \
    LIBBPF_LIB_DIR=/usr/lib/x86_64-linux-gnu

RUN cd agent-core && cargo build --release --locked && cd ..

# Build the final binary
COPY ./agent/build.rs ./agent/
COPY ./agent/src/ ./agent/src/
RUN cargo build --release --locked --bin agent

# Runtime stage
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary and vmlinux.h from the project's include directory
COPY --from=builder /workspace/target/release/agent /agent
COPY --from=builder /workspace/agent-core/bpf/include/vmlinux.h /usr/include/

# Set the entrypoint
ENTRYPOINT ["/agent"]
