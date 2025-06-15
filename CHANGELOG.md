# Changelog

All notable changes to the Pod-Agent project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial eBPF-based RASP agent implementation
- Comprehensive syscall monitoring capabilities
- gRPC-based communication with pod-controller
- Container context integration with Kubernetes metadata

## [0.1.0] - 2024-01-XX

### Added

#### Core eBPF Monitoring
- **Process Monitoring**
  - `execve` and `execveat` syscall tracing for process execution
  - `fork` event monitoring for process creation tracking
  - Process parent-child relationship mapping
  - Command name and argument capture

- **File System Operations**
  - `open` and `openat` syscall monitoring for file access tracking
  - `chmod`, `fchmod`, and `fchmodat` monitoring for permission changes
  - `mount` and `umount2` syscall tracing for filesystem operations
  - Path extraction and file operation context

- **Network Activity Monitoring**
  - `connect` syscall tracking for outbound connections
  - `bind` syscall monitoring for socket binding operations
  - `accept` and `accept4` tracking for incoming connections
  - `socket` creation monitoring with protocol detection
  - IPv4 address and port extraction

- **Security Operations Tracking**
  - `setuid` and `setgid` monitoring for privilege escalation detection
  - `ptrace` syscall tracking for process debugging attempts
  - `capset` monitoring for capability modifications
  - `bpf` syscall tracking for eBPF program loading
  - `seccomp` and `prctl` monitoring for syscall filtering changes

#### Agent Architecture
- **Rust-based Agent Binary**
  - Async event collection and processing
  - gRPC client with automatic reconnection
  - Robust error handling and recovery mechanisms
  - Container context extraction from cgroups

- **Core Library (`agent-core`)**
  - eBPF program management using libbpf-rs
  - Event parsing and structure conversion
  - Ring buffer-based event collection
  - Rate limiting to prevent event flooding

- **eBPF Programs**
  - Modular handler design for different event types
  - Efficient ring buffer communication
  - Per-PID rate limiting implementation
  - Container ID extraction from cgroup information

#### Communication & Integration
- **gRPC Protocol Implementation**
  - Agent registration and session management
  - Heartbeat mechanism for connection health
  - Streaming event transmission with acknowledgments
  - Automatic reconnection with exponential backoff

- **Kubernetes Integration**
  - DaemonSet deployment configuration
  - Container runtime metadata extraction
  - Support for Docker and containerd runtimes
  - Network policy for secure communication

- **Container Context Enrichment**
  - Container ID extraction from cgroup paths
  - Kubernetes pod and namespace metadata
  - Multi-runtime container detection
  - Process-to-container mapping

#### Deployment & Configuration
- **Docker Multi-stage Build**
  - Optimized container image with minimal runtime dependencies
  - eBPF compilation in build stage
  - Non-root container execution

- **Kubernetes Manifests**
  - DaemonSet configuration with required capabilities
  - Security context and volume mounts
  - Environment variable configuration
  - Network policy for controller communication

#### Event Processing Features
- **Comprehensive Event Structure**
  - Unified event format across all monitored syscalls
  - Timestamp tracking with nanosecond precision
  - Process context (PID, PPID, UID, GID)
  - Event-specific data fields

- **Rate Limiting & Performance**
  - Per-PID rate limiting to prevent event storms
  - Configurable burst limits and intervals
  - Efficient ring buffer usage
  - Minimal performance impact on monitored processes

#### Security & Permissions
- **Required Capabilities**
  - `CAP_SYS_ADMIN` for eBPF program loading
  - `CAP_BPF` for eBPF operations (kernel 5.8+)
  - `CAP_NET_ADMIN` for network monitoring
  - `CAP_TRACING` for tracepoint access

- **Volume Mounts**
  - `/sys/kernel/debug` for eBPF filesystem access
  - `/proc` for process information
  - `/sys/fs/bpf` for BPF filesystem operations

### Technical Implementation Details

#### eBPF Programs (`agent-core/bpf/`)
- **Core Event Handling** (`core/event_handling.h`)
  - Common event initialization functions
  - Rate limiting implementation
  - Container ID extraction logic

- **Specialized Handlers**
  - `exec_handler.h`: Process execution events
  - `file_handler.h`: File system operations
  - `network_handler.h`: Network activity monitoring
  - `security_handler.h`: Security-sensitive operations

- **Type Definitions** (`include/types.h`)
  - Unified event structure with union for event-specific data
  - Network information structures
  - Security operation data types

#### Rust Implementation
- **Event Processing** (`src/events/`)
  - Event parsing from raw eBPF data
  - Type-safe event structure definitions
  - JSON serialization support

- **Syscall Monitoring** (`src/syscalls/`)
  - eBPF program lifecycle management
  - Ring buffer setup and polling
  - Event callback handling

- **Utilities** (`src/utils/`)
  - String conversion helpers
  - Container context extraction
  - Error handling utilities

### Dependencies

#### System Requirements
- Linux kernel ≥ 5.8 with eBPF support
- BTF (BPF Type Format) support
- Container runtime (Docker, containerd)

#### Rust Dependencies
- `libbpf-rs` 0.20: eBPF program management
- `tokio` 1.0: Async runtime
- `tonic` 0.11: gRPC client implementation
- `prost` 0.12: Protocol buffer support
- `serde` 1.0: Serialization framework
- `anyhow` 1.0: Error handling
- `log` 0.4: Logging framework

#### Build Dependencies
- `libbpf-cargo` 0.21: eBPF build integration
- `tonic-build` 0.11: gRPC code generation
- `clang` ≥14: eBPF compilation
- `protobuf-compiler`: Protocol buffer compilation

### Configuration Options

#### Environment Variables
- `CONTROLLER_ENDPOINT`: gRPC controller endpoint (default: `rasp-controller.default.svc:50051`)
- `RUST_LOG`: Rust logging level (default: `info`)
- `DEBUG`: Debug mode flag (default: `info`)
- `NODE_NAME`: Kubernetes node name (auto-detected)
- `POD_NAME`: Agent pod name (auto-detected)
- `POD_NAMESPACE`: Pod namespace (auto-detected)
- `CONTAINER_ID`: Container ID (auto-detected)

#### Performance Tuning
- Event channel size: 50,000 events
- Event batch size: 1,000 events
- Batch timeout: 500ms
- BPF poll timeout: 500ms
- Rate limit interval: 1 second
- Rate limit burst: 100 events per second

### Known Limitations
- IPv6 network monitoring not fully implemented
- Limited to tracepoint-based monitoring (no kprobe support yet)
- Container context extraction may fail for some runtime configurations
- Requires privileged container execution

### Breaking Changes
- N/A (Initial release)

### Deprecated Features
- N/A (Initial release)

### Security Considerations
- Agent runs with elevated privileges (required for eBPF)
- Network communication secured via Kubernetes service mesh
- Event data may contain sensitive information (file paths, network destinations)
- Container context extraction accesses host filesystem

---

## Development Notes

### Build System
- Cargo workspace with two crates: `agent` (binary) and `agent-core` (library)
- eBPF programs compiled during build using `libbpf-cargo`
- Protobuf definitions shared between agent and controller
- Multi-stage Docker build for optimized production images

### Testing Strategy
- Unit tests for Rust components
- Integration tests with mock controller
- End-to-end testing in Kubernetes environment
- Performance benchmarking for event processing throughput

### Future Roadmap
- IPv6 network monitoring support
- Enhanced container runtime compatibility
- Advanced filtering and aggregation capabilities
- Real-time threat detection integration
- Performance optimizations and resource usage reduction 