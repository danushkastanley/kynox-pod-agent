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

    // Build and generate skeleton
    let builder = SkeletonBuilder::new()
        .source(&bpf_src);

    // If we have custom clang, use it
    if let Ok(clang) = env::var("BPF_CLANG") {
        builder.clang(&clang);
    }

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
