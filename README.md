# eBPF RASP Agent (pod-level)

This repository contains a Rust-based pod-level Runtime Application Self-Protection (RASP) agent that uses eBPF to trace `execve` syscalls and stream events to user space.

## Prerequisites (Linux VM)

- **Kernel**: Linux ≥ 5.8 with headers installed
- **Rust**: latest stable toolchain (via [rustup](https://rustup.rs/))
- **Clang/LLVM**: clang (≥10) and llvm
- **Build tools**: `build-essential`, `gcc`, `make`, `pkg-config`
- **Libs for eBPF**: `libelf-dev`, `libbpf-dev` (or manual libbpf headers)
- **Optional**: Docker (for containerized testing)

On Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y clang llvm build-essential gcc make pkg-config libelf-dev libbpf-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## Repository Layout

```
pod-agent/
├── Cargo.toml          # Workspace root
├── README.md           # This file
└── agent/              # eBPF agent crate
    ├── Cargo.toml      # Agent crate with libbpf-cargo build
    ├── build.rs        # Compiles BPF C into Rust skeleton
    ├── bpf/            # eBPF program sources
    │   └── exec_monitor.bpf.c
    └── src/
        └── main.rs     # User-space reader & printer
```

## Build & Run

1. **Build** the agent (this will compile both BPF and user-space):
   ```bash
   cd agent
   cargo build --release
   ```

2. **Mount BPF filesystem** (if not already):
   ```bash
   sudo mount -t bpf none /sys/fs/bpf
   ```

3. **Run** the agent (requires capabilities to load BPF programs):
   ```bash
   sudo ./target/release/agent
   ```

You should see JSON-formatted `execve` events printed to stdout.

## Next Steps

- Add more eBPF hooks (file opens, `ptrace`, etc.)
- Integrate gRPC streaming with mTLS
- Create Helm chart for Kubernetes deployment
- Implement test cases (reverse shells, privilege escalation)

---
*Built for Linux VM environment.*
