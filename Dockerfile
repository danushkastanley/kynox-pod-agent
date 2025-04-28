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
    && rm -rf /var/lib/apt/lists/*

# Set up clang-14 as the default
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 100 && \
    update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-14 100

# Install Rust via rustup
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
# Install Rust via rustup and add rustfmt component in the same layer
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable && \
    /usr/local/cargo/bin/rustup component add rustfmt

# Link headers (might still be needed depending on include paths)
RUN ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm || true
RUN ln -sf /usr/include/linux /usr/include/linux || true

WORKDIR /workspace

# --- Optimized Build Steps ---

# 1. Copy manifests and create dummy src for dependency build
COPY ./Cargo.toml ./Cargo.lock /workspace/
COPY ./agent/Cargo.toml /workspace/agent/
WORKDIR /workspace
RUN mkdir -p agent/src && echo "fn main() {}" > agent/src/main.rs

# 2. Build *only* dependencies
WORKDIR /workspace/agent
# Ensure target directory exists for caching
RUN cargo fetch # Downloads deps but doesn't build them initially
RUN cargo build --release --bin agent || true # Build deps, ignore error if main doesn't exist yet (it does now)

# 3. Copy the actual source code
WORKDIR /workspace
COPY ./agent/src/ ./agent/src/
COPY ./agent/bpf/ ./agent/bpf/
COPY ./agent/build.rs ./agent/
COPY ./vmlinux.h /usr/include/

# 4. Build the final binary (will reuse dependency cache)
WORKDIR /workspace/agent
ENV LIBBPF_PATH=/usr/lib/x86_64-linux-gnu
RUN cargo build --release --bin agent

# Runtime stage (optional minimal image)
FROM ubuntu:22.04 AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/agent /agent
# Copy vmlinux.h (only if strictly needed at runtime - unlikely with libbpf)
COPY --from=builder /usr/include/vmlinux.h /usr/include/

ENTRYPOINT ["/agent"]
