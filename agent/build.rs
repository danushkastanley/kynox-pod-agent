use libbpf_cargo::SkeletonBuilder;
use std::{env, error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let skel_path = out_dir.join("exec_monitor.skel.rs"); // Explicit path for the skeleton file
    SkeletonBuilder::default()
        .source("bpf/exec_monitor.bpf.c")
        .build_and_generate(&skel_path)?;
    Ok(())
}
