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
    TMPDIR=/tmp \
    LIBELF_INCLUDE_DIR=/usr/include \
    LIBBPF_INCLUDE_DIR=/usr/include \
    LIBBPF_LIB_DIR=/usr/lib/x86_64-linux-gnu

# Set up proper BPF CFLAGS
ENV BPF_CFLAGS="-I/usr/include/x86_64-linux-gnu \
    -I/usr/include/linux \
    -I/usr/include \
    -D__TARGET_ARCH_x86 \
    -D__x86_64__ \
    -D__BPF_TRACING__ \
    -Wno-unused-value \
    -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types \
    -Wno-gnu-variable-sized-type-not-at-end \
    -Wno-address-of-packed-member \
    -Wno-tautological-compare \
    -Wno-unknown-warning-option"

# Install Rust and components
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable && \
    /usr/local/cargo/bin/rustup component add rustfmt

# Set up kernel headers and BPF infrastructure
RUN mkdir -p /tmp && chmod 1777 /tmp && \
    mkdir -p /usr/src/linux/tools/lib/bpf && \
    touch /usr/src/linux/tools/lib/bpf/libbpf.a && \
    ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm && \
    ln -sf /usr/include/linux /usr/include/linux && \
    ln -sf /usr/lib/x86_64-linux-gnu/libbpf.so /usr/lib/libbpf.so

WORKDIR /workspace

# Copy only necessary files for building
COPY Cargo.toml Cargo.lock ./
COPY agent/Cargo.toml agent/
COPY agent-core/Cargo.toml agent-core/

# Create dummy source files for dependencies caching
RUN mkdir -p agent/src agent-core/src && \
    touch agent/src/lib.rs agent-core/src/lib.rs && \
    cargo build --release

# Copy actual source files
COPY . .

# Build the agent
ENV LIBBPF_PATH=/usr/lib/x86_64-linux-gnu
RUN cargo build --release --bin agent

# Runtime stage
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1 \
    libbpf0 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/agent /usr/local/bin/

# Create mount points for BPF filesystems
# These will be mounted at runtime with proper permissions
VOLUME ["/sys/fs/bpf", "/sys/kernel/debug"]

ENTRYPOINT ["/usr/local/bin/agent"]
