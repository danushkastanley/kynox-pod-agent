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
    linux-tools-common \
    linux-tools-generic \
    zlib1g-dev \
    libz-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set up clang-14 as the default
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 100 && \
    update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-14 100

# Install Rust via rustup
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    BPF_CLANG=clang-14 \
    BPF_CFLAGS="-I/usr/include/x86_64-linux-gnu -I/usr/include/linux -I/usr/include/asm" \
    TMPDIR=/tmp

# Install Rust via rustup and add rustfmt component in the same layer
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable && \
    /usr/local/cargo/bin/rustup component add rustfmt

# Ensure proper temporary directory permissions
RUN mkdir -p /tmp && chmod 1777 /tmp

# Set up kernel headers and symlinks
RUN ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm && \
    ln -sf /usr/include/linux /usr/include/linux && \
    ln -sf /usr/lib/x86_64-linux-gnu/libbpf.so /usr/lib/libbpf.so && \
    mkdir -p /usr/src/linux/tools/lib/bpf && \
    touch /usr/src/linux/tools/lib/bpf/libbpf.a

WORKDIR /workspace

# --- Optimized Build Steps ---

# 1. Copy manifests and create dummy src for dependency build
COPY ./Cargo.toml ./Cargo.lock /workspace/
COPY ./agent/Cargo.toml /workspace/agent/
COPY ./agent-core/Cargo.toml /workspace/agent-core/
WORKDIR /workspace
RUN mkdir -p agent/src agent-core/src && echo "fn main() {}" > agent/src/main.rs && echo "pub fn dummy() {}" > agent-core/src/lib.rs

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
COPY ./agent-core/src/ ./agent-core/src/
COPY ./agent-core/bpf/ ./agent-core/bpf/
COPY ./agent-core/build.rs ./agent-core/
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
