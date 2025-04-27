# Multi-stage Dockerfile to build the eBPF RASP agent on Linux

# Builder stage
FROM --platform=linux/amd64 rust:latest AS builder

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
        clang \
        llvm \
        libelf-dev \
        libbpf-dev \
        pkg-config \
        build-essential \
        linux-headers-amd64 \
        linux-libc-dev \
        git \
        bpftool \
        && rm -rf /var/lib/apt/lists/*

# Set up kernel headers
RUN apt-get update && \
    apt-get install -y linux-headers-amd64 && \
    ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm && \
    ln -sf /usr/include/linux /usr/include/linux && \
    rm -rf /var/lib/apt/lists/*

# Generate vmlinux.h
RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > /usr/include/vmlinux.h

# Install rustfmt
RUN rustup component add rustfmt

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
COPY --from=builder /workspace/target/release/agent /agent
ENTRYPOINT /agent # Use shell form
