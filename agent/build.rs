use libbpf_cargo::SkeletonBuilder;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    SkeletonBuilder::default()
        .source("bpf/exec_monitor.bpf.c")
        .build_and_generate()?;
    Ok(())
}
