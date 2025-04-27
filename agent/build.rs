use libbpf_cargo::SkeletonBuilder;
use std::{error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = manifest_dir.join("bpf").join("exec_monitor.bpf.c");
    let out_dir = manifest_dir.join("src").join("bpf");
    
    // Create output directory if it doesn't exist
    std::fs::create_dir_all(&out_dir)?;
    
    let skel_path = out_dir.join("generated_skel.rs");

    // Build and generate skeleton
    SkeletonBuilder::default()
        .source(&source)
        .clang_args("-I/usr/include")
        .clang_args("-I/usr/include/x86_64-linux-gnu")
        .clang_args("-I/usr/lib/llvm-14/lib/clang/14.0.0/include")
        .debug(true) // Enable debug output
        .build_and_generate(&skel_path)?;

    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed={}", skel_path.display());
    Ok(())
}
