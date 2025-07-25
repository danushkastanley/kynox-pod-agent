# Pod-Agent: eBPF-based RASP Agent for Kubernetes

A high-performance Runtime Application Self-Protection (RASP) agent for Kubernetes environments, leveraging eBPF technology for real-time system call monitoring and security event detection. This agent provides comprehensive visibility into container activities and security-relevant system calls with minimal performance overhead.

## Features

### Process Monitoring
- **Process Execution**: Tracks `execve` and `execveat` system calls with full command-line arguments
- **Process Lifecycle**: Monitors process creation (`fork`), termination, and parent-child relationships
- **Command Tracking**: Captures process communication names and execution context

### File System Monitoring
- **File Access**: Monitors `open`, `openat` operations with path tracking
- **Permission Changes**: Tracks `chmod`, `fchmod`, `fchmodat` operations
- **Mount Operations**: Detects mount/unmount operations for filesystem security
- **Directory Operations**: Comprehensive file system activity monitoring

### Network Activity Monitoring
- **Connection Tracking**: Monitors outbound connections (`connect`) with destination IP/port
- **Socket Operations**: Tracks socket creation, binding (`bind`), and listening operations
- **Inbound Connections**: Monitors incoming connections (`accept`, `accept4`)
- **Protocol Support**: IPv4 and IPv6 network monitoring

### Security Operations Monitoring
- **Privilege Escalation**: Detects `setuid`/`setgid` operations and capability changes
- **Process Debugging**: Monitors `ptrace` system calls for potential code injection
- **Security Mechanisms**: Tracks seccomp and BPF program loading operations
- **Capability Management**: Monitors `capset` operations for privilege modifications

### Container Context Integration
- **Container Identification**: Extracts container IDs from cgroup information
- **Kubernetes Metadata**: Enriches events with pod names, namespaces, and container names
- **Multi-Runtime Support**: Works with Docker, containerd, and other container runtimes

## Architecture

```
pod-agent/
├── Cargo.toml                    # Workspace configuration
├── agent/                        # Main agent binary
│   ├── Cargo.toml               # Agent dependencies
│   ├── build.rs                 # Build-time protobuf generation
│   └── src/
│       ├── main.rs              # Agent entry point and main logic
│       ├── connection.rs        # gRPC connection management
│       └── utils.rs             # Container context utilities
├── agent-core/                   # Core eBPF library
│   ├── Cargo.toml              # Core library dependencies
│   ├── build.rs                # eBPF build configuration
│   ├── src/                    # Rust implementation
│   │   ├── lib.rs              # Public API and constants
│   │   ├── events/             # Event structures and parsing
│   │   ├── syscalls/           # Syscall monitoring logic
│   │   └── utils/              # Utility functions
│   └── bpf/                    # eBPF programs (C)
│       ├── exec_monitor.bpf.c  # Main eBPF program
│       ├── core/               # Core eBPF utilities
│       ├── handlers/           # Event-specific handlers
│       └── include/            # eBPF headers and types
├── telemetry.proto              # gRPC service definitions
├── Dockerfile                   # Multi-stage container build
└── *.yaml                      # Kubernetes deployment manifests
```

### Core Components

#### Agent Binary (`agent/`)
- **Main Logic**: Event collection, gRPC communication, reconnection handling
- **Connection Management**: Robust gRPC client with heartbeat and automatic reconnection
- **Container Context**: Extracts Kubernetes metadata from container runtime

#### Agent Core Library (`agent-core/`)
- **eBPF Management**: Loads and manages eBPF programs using libbpf-rs
- **Event Processing**: Parses raw eBPF events into structured data
- **Ring Buffer**: Efficient event collection via eBPF ring buffers

#### eBPF Programs (`agent-core/bpf/`)
- **Tracepoint Handlers**: Attach to kernel tracepoints for syscall monitoring
- **Event Structures**: Shared data structures between kernel and userspace
- **Rate Limiting**: Prevents event flooding with per-PID rate limiting

## Prerequisites

### System Requirements
- **Linux Kernel**: ≥ 5.8 with eBPF support and kernel headers
- **Container Runtime**: Docker, containerd, or compatible runtime
- **Kubernetes**: Any supported version

### Development Requirements
- **Rust Toolchain**: Stable Rust (1.70+)
- **Clang/LLVM**: Version 14 or higher for eBPF compilation
- **Build Tools**: `build-essential`, `pkg-config`
- **Libraries**: `libelf-dev`, `libbpf-dev`

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
    linux-headers-generic \
    protobuf-compiler

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Set up clang alternatives
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 100
sudo update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-14 100
```

## Building

### Using Docker (Recommended)

```bash
# Build the container image
docker buildx build --platform linux/amd64 -t pod-agent:latest .

# Run locally for testing
docker run --privileged --pid=host pod-agent:latest
```

### Manual Build

```bash
# Clone the repository
git clone <repository-url>
cd pod-agent

# Build the core library first
cd agent-core
cargo build --release

# Build the main agent
cd ../agent
cargo build --release

# The binary will be at target/release/agent
```

## Deployment

### Kubernetes DaemonSet Deployment

1. **Build and load the image**:
   ```bash
   # Build the image
   docker build -t pod-agent:latest .
   
   # For k3s: import into containerd
   docker save pod-agent:latest | sudo k3s ctr images import -
   ```

2. **Apply network policy** (optional):
   ```bash
   kubectl apply -f network-policy.yaml
   ```

3. **Deploy the DaemonSet**:
   ```bash
   kubectl apply -f pod-agent-daemonset.yaml
   ```

### Required Capabilities and Permissions

The agent requires the following capabilities:
- `CAP_SYS_ADMIN`: For loading eBPF programs
- `CAP_BPF`: For eBPF operations (kernel 5.8+)
- `CAP_NET_ADMIN`: For network monitoring
- `CAP_TRACING`: For tracepoint access

Volume mounts required:
- `/sys/kernel/debug`: eBPF filesystem access
- `/proc`: Process information
- `/sys/fs/bpf`: BPF filesystem

## Configuration

Configure the agent via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `CONTROLLER_ENDPOINT` | gRPC controller endpoint | `rasp-controller.default.svc:50051` |
| `RUST_LOG` | Rust log level | `info` |
| `DEBUG` | Debug mode | `info` |
| `NODE_NAME` | Kubernetes node name | Auto-detected |
| `POD_NAME` | Agent pod name | Auto-detected |
| `POD_NAMESPACE` | Pod namespace | Auto-detected |

### Example Configuration

```yaml
env:
  - name: CONTROLLER_ENDPOINT
    value: "rasp-controller.security.svc:50051"
  - name: RUST_LOG
    value: "debug"
  - name: NODE_NAME
    valueFrom:
      fieldRef:
        fieldPath: spec.nodeName
```

## Monitored Events

### Event Types and Classifications

| Event Type | Syscalls | Description |
|------------|----------|-------------|
| `EXEC` | `execve`, `execveat` | Process execution |
| `FORK` | `fork`, `clone` | Process creation |
| `OPEN` | `open`, `openat` | File access |
| `CONNECT` | `connect` | Network connections |
| `BIND` | `bind` | Socket binding |
| `ACCEPT` | `accept`, `accept4` | Incoming connections |
| `SOCKET` | `socket` | Socket creation |
| `SETUID` | `setuid` | User ID changes |
| `SETGID` | `setgid` | Group ID changes |
| `PTRACE` | `ptrace` | Process debugging |
| `MOUNT` | `mount` | Filesystem mounting |
| `UMOUNT` | `umount2` | Filesystem unmounting |
| `CAPSET` | `capset` | Capability changes |
| `BPF_PROG` | `bpf` | eBPF program loading |
| `SECCOMP` | `seccomp`, `prctl` | Syscall filtering |
| `CHMOD` | `chmod`, `fchmod`, `fchmodat` | Permission changes |

### Event Data Structure

```rust
pub struct EventOutput {
    pub event_type: u32,
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub comm: String,
    pub container_id: Option<String>,
    pub filename: Option<String>,
    pub timestamp: u64,
    // Network information
    pub daddr: Option<String>,
    pub dport: Option<u16>,
    // Security context
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    // Event-specific data...
}
```

## Communication Protocol

### gRPC Service Interface

The agent communicates with the pod-controller via gRPC:

```protobuf
service TelemetryService {
  rpc ConnectAgent(ConnectRequest) returns (ConnectResponse);
  rpc SendHeartbeat(Heartbeat) returns (ConnectionStatus);
  rpc StreamEvents(stream SecurityEvent) returns (SendEventsResponse);
}
```

### Connection Lifecycle

1. **Initial Connection**: Agent connects with node/pod metadata
2. **Session Establishment**: Controller returns session ID
3. **Heartbeat Loop**: Periodic health checks every 30 seconds
4. **Event Streaming**: Continuous event stream with acknowledgments
5. **Reconnection**: Automatic reconnection on connection loss

## Troubleshooting

### Common Issues

#### eBPF Program Loading Fails
```bash
# Check kernel version and BTF support
uname -r
ls /sys/kernel/btf/

# Verify capabilities
kubectl describe pod <pod-name>
```

#### No Events Generated
```bash
# Check eBPF program status
kubectl logs <pod-name> | grep -i bpf

# Verify container runtime paths
kubectl exec <pod-name> -- ls -la /var/lib/docker/containers/
```

#### Connection Issues
```bash
# Test controller connectivity
kubectl exec <pod-name> -- nc -zv rasp-controller.default.svc 50051

# Check network policy
kubectl get networkpolicy
```

### Debug Mode

Enable debug logging for detailed troubleshooting:

```yaml
env:
  - name: RUST_LOG
    value: "debug"
  - name: DEBUG
    value: "debug"
```

## Testing

### Unit Tests
```bash
cd agent-core
cargo test

cd ../agent
cargo test
```

### Integration Testing
```bash
# Deploy to test cluster
kubectl apply -f pod-agent-daemonset.yaml

# Monitor logs
kubectl logs -f -l app=pod-agent

# Generate test events
kubectl exec <test-pod> -- /bin/sh -c "echo 'test' > /tmp/test.txt"
```

## Performance Considerations

### Resource Usage
- **CPU**: ~50-100m per node
- **Memory**: ~128-256MB per node
- **Network**: Minimal overhead for event streaming

### Rate Limiting
- Built-in per-PID rate limiting prevents event flooding
- Configurable burst limits and intervals
- Automatic backpressure handling

### eBPF Efficiency
- Zero-copy event collection via ring buffers
- Minimal kernel overhead with tracepoint attachment
- Efficient filtering in kernel space

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow Rust best practices and conventions
- Add tests for new functionality
- Update documentation for API changes
- Ensure eBPF programs are properly formatted

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Built for Kubernetes environments with eBPF technology**
