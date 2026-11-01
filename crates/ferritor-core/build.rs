//! Compiles the gRPC protos. Requires `protoc` on PATH (or set `PROTOC`).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `proto/` is outside this package, so cargo's default (rerun when any
    // package file changes) never sees proto edits.
    println!("cargo:rerun-if-changed=../../proto");
    tonic_prost_build::configure().compile_protos(
        &["../../proto/ferritor/v1/ferritor.proto"],
        &["../../proto"],
    )?;
    Ok(())
}
