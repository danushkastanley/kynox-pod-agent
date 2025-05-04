use libbpf_cargo::SkeletonBuilder;
use std::{env, path::PathBuf};

const BPF_SRC: &str = "bpf/exec_monitor.bpf.c";

fn main() {
    // Set up paths
    let skel = PathBuf::from("src/bpf/generated_skel.rs");
    let bpf_src = PathBuf::from(BPF_SRC);
    
    // Ensure output directory exists
    if let Some(parent) = skel.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }

    // Set up BPF compilation environment
    println!("cargo:rerun-if-env-changed=LIBELF_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=LIBBPF_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=LIBBPF_LIB_DIR");
    println!("cargo:rerun-if-env-changed=BPF_CLANG");
    println!("cargo:rerun-if-env-changed=BPF_CFLAGS");

    // Get include paths from environment variables
    let libelf_include_dir = env::var("LIBELF_INCLUDE_DIR").unwrap_or_else(|_| "/usr/include".to_string());
    let libbpf_include_dir = env::var("LIBBPF_INCLUDE_DIR").unwrap_or_else(|_| "/usr/include".to_string());

    // Get BPF compiler and flags
    let clang = env::var("BPF_CLANG").unwrap_or_else(|_| "clang".to_string());
    let cflags = env::var("BPF_CFLAGS").unwrap_or_default();

    // Create a new builder instance that lives long enough
    let mut builder = SkeletonBuilder::new();
    builder.source(&bpf_src);

    // Configure clang if specified
    builder.clang(&clang);

    // Create clang args string
    let clang_args = format!(
        "-g -O2 -target bpf -D__TARGET_ARCH_x86 -I{} -I{} -I/usr/include/x86_64-linux-gnu -I/usr/include -I./bpf/include {}",
        libelf_include_dir, libbpf_include_dir, cflags
    );

    // Add clang args
    builder.clang_args(&clang_args);

    // Build with proper error handling
    match builder.build_and_generate(&skel) {
        Ok(_) => println!("Successfully generated BPF skeleton"),
        Err(e) => {
            eprintln!("Failed to generate BPF skeleton: {}", e);
            std::process::exit(1);
        }
    }

    // Mark source as dependency for rebuild
    println!("cargo:rerun-if-changed={}", BPF_SRC);
}
