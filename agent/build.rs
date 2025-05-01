fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Define the path to the proto file relative to the Cargo.toml of the *agent* crate
    let proto_path = "../telemetry.proto";
    //let proto_dir = ".."; // Directory containing telemetry.proto and potential imports (No longer needed?)

    // Tell cargo to rerun the build script if the proto file changes
    println!("cargo:rerun-if-changed={}", proto_path);

    // Compile the proto file
    tonic_build::configure()
        .extern_path(".google.protobuf", "::prost_types") // Map google.protobuf
        .compile_well_known_types(true)
        .compile(
            &[proto_path], // List of proto files to compile
            &[".."] // Keep this to find telemetry.proto relative to build.rs
            //&[proto_dir],  // Directory to search for includes (relative to build script)
        )?;

    Ok(())
}
