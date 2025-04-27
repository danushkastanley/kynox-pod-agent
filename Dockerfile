# Multi-stage Dockerfile to build the eBPF RASP agent on Linux

# Builder stage
FROM --platform=linux/amd64 debian:bullseye AS builder

# Install common dependencies and rustup prerequisites
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Rust via rustup
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable

# Install eBPF/agent dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    pkg-config \
    linux-headers-amd64 \
    linux-libc-dev \
    git \
    bpftool \
    && rm -rf /var/lib/apt/lists/*

# Link headers (might still be needed depending on include paths)
RUN ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm || true
RUN ln -sf /usr/include/linux /usr/include/linux || true

# Generate vmlinux.h - Removed as it fails in docker build and may not be needed
# RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > /usr/include/vmlinux.h

# Install rustfmt
RUN /usr/local/cargo/bin/rustup component add rustfmt

WORKDIR /workspace
COPY . .

# Build agent (compiles BPF + user-space)
WORKDIR /workspace/agent
RUN pwd
RUN ls -l /workspace/agent
ENV LIBBPF_PATH=/usr/lib/x86_64-linux-gnu
RUN cargo build --release
RUN ls -la /workspace/target/release/agent # Verify agent binary exists before runtime stage

# Runtime stage (optional minimal image)
FROM debian:bullseye-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/agent /agent
ENTRYPOINT /agent # Use shell form
