
# eBPF-Powered RASP Agent for Kubernetes

## 🧠 Objective
Design and implement a lightweight **pod-level runtime security agent** using **eBPF (extended Berkeley Packet Filter)**, to be deployed in a **Kubernetes cluster**.

### The Agent Must:
- Monitor syscalls, file access, and network activity inside its host pod.
- Send telemetry data securely to a **centralized controller module**.
- Detect real-time malicious behavior (e.g., privilege escalation, container breakout).
- Be **language-agnostic**, and optimized for minimal performance overhead.

## 🧱 Tech Stack & Tools

### Programming Languages
- **Rust**: For writing eBPF programs
- **BCC** or **libbpf-rs**: Kernel interactions
- **gRPC with mTLS**: Controller communication

### Build/CI
- `cargo`, Docker
- GitHub Actions or Buildkite
- ArgoCD

### Environment
- Kubernetes (Minikube for local, EKS for cloud)
- Linux Kernel ≥ 5.8 (eBPF supported)
- Prometheus & Grafana (optional)

## ✅ Key Agent Features

1. **eBPF Hooks**
    - Syscall tracing, file monitoring, exec tracking, capabilities usage
2. **Real-Time Telemetry**
    - Protobuf + gRPC transmission, pod metadata
3. **Lightweight Design**
    - Perf/ring buffers, <5% overhead
4. **Secure Comms**
    - mTLS-secured gRPC, cert identity

## 🧪 Suggested Test Cases

| Category | Test Case | Expected Outcome |
|----------|-----------|------------------|
| File Access | Access `/etc/shadow` | Agent detects & flags |
| Priv Esc | `capsh`, `setcap` use | Alert triggered |
| Process Injection | `ptrace` injection | Anomaly detected |
| Reverse Shell | Unknown IP conn | Logged + blocked |
| Syscall Abuse | Rapid `clone()`, `mount()` | Alert + throttled |
| CPU Spike | Load test | <5% overhead |
| Agent Crash | Simulated failure | Auto-restart & alert |

## 🔐 Optional Features

- Self-healing via pod quarantine
- Learned policy feedback loop
- ELK/Loki logging integration

## 🧠 Sample Prompt for AI Agent

> “You're building a Kubernetes-native Runtime Application Self-Protection (RASP) agent using Rust + eBPF. This agent is deployed inside each pod and monitors syscalls and network activity. It sends real-time telemetry to a gRPC controller for centralized policy enforcement. Use minimal CPU and memory. Include automated tests for syscall tracing (e.g., `execve`, `setuid`, `ptrace`) and behavior anomalies like reverse shells or privilege escalation. Build the agent to be language-agnostic, secure via mTLS, and deployable via Helm. Optimize performance and ensure safe crash recovery.”
