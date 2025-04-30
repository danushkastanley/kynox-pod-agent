fn main() {
    // No build script needed as we use eBPF code from agent-core
    println!("cargo:rerun-if-changed=src/main.rs");
}
