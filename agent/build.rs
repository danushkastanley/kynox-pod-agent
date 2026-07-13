fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_path = "../telemetry.proto";

    println!("cargo:rerun-if-changed={}", proto_path);

    tonic_build::configure()
        .extern_path(".google.protobuf", "::prost_types")
        .compile_well_known_types(true)
        .compile_protos(&[proto_path], &[".."])?;

    Ok(())
}
