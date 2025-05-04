# Pod-Agent: eBPF-based RASP for Kubernetes

A comprehensive Runtime Application Self-Protection (RASP) system for Kubernetes environments, leveraging eBPF for real-time monitoring and security enforcement. This agent provides deep visibility into container activities and security-relevant system calls.

## Features

- **Process Monitoring**
  - Process creation and execution (`execve`)
  - Process forking and termination
  - Command-line argument tracking

- **File System Monitoring**
  - File access and modifications
  - Directory operations
  - Mount/unmount operations

- **Network Activity**
  - Connection attempts
  - Bind operations
  - Accept calls

- **Security Operations**
  - Capability changes
  - Seccomp operations
  - BPF program loading
  - ptrace system calls
  - setuid/setgid operations

## Architecture

```
pod-agent/
├── Cargo.toml                # Workspace manifest
├── agent/                    # Main agent binary
│   ├── Cargo.toml
│   ├── build.rs             # Build configuration
│   └── src/
│       └── main.rs          # Agent entry point
└── agent-core/              # Core library
    ├── Cargo.toml
    ├── build.rs
    ├── src/                 # Rust implementation
    │   ├── events.rs
    │   ├── syscalls/
    │   └── ...
    └── bpf/                 # eBPF implementation
        ├── core/
        │   └── event_handling.h
        ├── handlers/
        │   ├── exec_handler.h
        │   ├── file_handler.h
        │   ├── network_handler.h
        │   └── security_handler.h
        └── include/
            ├── common.h
            ├── constants.h
            ├── types.h
            └── vmlinux.h
```

## Prerequisites

- Linux kernel ≥ 5.8 with headers
- Docker for containerized deployment
- For development:
  - Rust toolchain (stable)
  - clang/LLVM (≥14)
  - libelf-dev, libbpf-dev
  - build-essential, pkg-config

### Development Setup (Ubuntu/Debian)

```bash
# Install system dependencies
sudo apt-get update && sudo apt-get install -y \
    build-essential \
    clang-14 \
    llvm-14 \
    libelf-dev \
    libbpf-dev \
    pkg-config \
    linux-headers-generic

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## Building

### Using Docker (Recommended)

```bash
# Build the container
docker buildx build --platform linux/amd64 -t pod-agent:latest .

# Run the container
docker run --privileged pod-agent:latest
```

### Manual Build

```bash
# Build the core library
cd agent-core
cargo build --release

# Build the agent binary
cd ../agent
cargo build --release
```

## Deployment

### Kubernetes Setup

1. Apply the RBAC configuration:
   ```bash
   kubectl apply -f k8s/rbac.yaml
   ```

2. Deploy the controller:
   ```bash
   kubectl apply -f k8s/controller.yaml
   ```

3. Deploy the agent DaemonSet:
   ```bash
   kubectl apply -f k8s/agent.yaml
   ```

### Required Capabilities

The agent requires the following capabilities:
- `CAP_BPF` for loading eBPF programs
- `CAP_TRACING` for syscall tracing
- `CAP_SYS_ADMIN` for certain BPF operations

## Configuration

The agent can be configured via environment variables:

```yaml
env:
  - name: LOG_LEVEL
    value: "info"
  - name: CONTROLLER_ENDPOINT
    value: "rasp-controller.default.svc.cluster.local:50051"
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---
*For detailed technical documentation and API references, please visit the [Wiki](../../wiki).*
