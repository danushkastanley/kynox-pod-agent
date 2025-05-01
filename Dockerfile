# Multi-stage Dockerfile to build the eBPF RASP agent on Linux

# Builder stage
FROM --platform=linux/amd64 ubuntu:22.04 AS builder

# Install common dependencies and rustup prerequisites
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    build-essential \
    libc6-dev \
    clang-14 \
    llvm-14 \
    libelf-dev \
    libbpf-dev \
    pkg-config \
    linux-headers-generic \
    linux-libc-dev \
    git \
    linux-tools-generic \
    protobuf-compiler \
    libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*

# Set up clang-14 as the default
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 100 && \
    update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-14 100

# Install Rust via rustup
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    BPF_CLANG=clang-14 \
    LIBELF_INCLUDE_DIR=/usr/include \
    LIBBPF_INCLUDE_DIR=/usr/include \
    LIBBPF_LIB_DIR=/usr/lib/x86_64-linux-gnu

# Install Rust and components
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable && \
    /usr/local/cargo/bin/rustup component add rustfmt

# Link headers
RUN ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm && \
    ln -sf /usr/include/linux /usr/include/linux && \
    ln -sf /usr/lib/x86_64-linux-gnu/libbpf.so /usr/lib/libbpf.so

WORKDIR /workspace

# --- Optimized Build Steps ---

# 1. Copy manifests and create dummy src for dependency build
COPY ./Cargo.toml ./Cargo.lock /workspace/
COPY ./agent/Cargo.toml /workspace/agent/
COPY ./agent-core/Cargo.toml /workspace/agent-core/
COPY ./telemetry.proto /workspace/

# 2. Create dummy source files for dependencies caching
RUN mkdir -p agent/src agent-core/src && \
    echo "fn main() {}" > agent/src/main.rs && \
    echo "pub fn dummy() {}" > agent-core/src/lib.rs

# 3. Build dependencies
RUN cargo fetch
RUN cargo build --release || true

# 4. Copy the actual source code
COPY ./agent/src/ ./agent/src/
COPY ./agent/build.rs ./agent/
COPY ./agent-core/src/ ./agent-core/src/
COPY ./agent-core/bpf/ ./agent-core/bpf/
COPY ./agent-core/build.rs ./agent-core/
COPY ./vmlinux.h /usr/include/

# 5. Build the final binary
ENV LIBBPF_PATH=/usr/lib/x86_64-linux-gnu
RUN cargo build --release --bin agent

# Runtime stage
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/agent /agent
COPY --from=builder /usr/include/vmlinux.h /usr/include/

ENTRYPOINT ["/agent"]
