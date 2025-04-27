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
COPY . .

# Create output directory for BPF skeleton
RUN mkdir -p /workspace/agent/src/bpf

# Copy vmlinux.h to the include path
COPY vmlinux.h /usr/include/vmlinux.h

# Build agent (compiles BPF + user-space)
WORKDIR /workspace/agent
RUN pwd
RUN ls -l /workspace/agent
ENV LIBBPF_PATH=/usr/lib/x86_64-linux-gnu

# Debug: Run cargo build directly first to see skeleton generation
RUN cargo build
RUN ls -la /workspace/agent/src/bpf/
RUN cat /workspace/agent/src/bpf/generated_skel.rs || true

# Then try the release build
RUN cargo build --release
RUN ls -la /workspace/target/release/agent # Verify agent binary exists before runtime stage

# Runtime stage (optional minimal image)
FROM ubuntu:22.04 AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/agent /agent
COPY --from=builder /usr/include/vmlinux.h /usr/include/vmlinux.h

ENTRYPOINT ["/agent"]
