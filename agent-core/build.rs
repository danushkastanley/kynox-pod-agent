use libbpf_cargo::SkeletonBuilder;
use std::path::PathBuf;

const BPF_SRC: &str = "bpf/exec_monitor.bpf.c";

fn main() {
    let skel = PathBuf::from("src/bpf/generated_skel.rs");
    let bpf_src = PathBuf::from(BPF_SRC);

    SkeletonBuilder::new()
        .source(&bpf_src)
        .build_and_generate(&skel)
        .unwrap();
    println!("cargo:rerun-if-changed={}", BPF_SRC);
}
