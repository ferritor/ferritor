//! Compiles the Secrets Store CSI Driver's provider API (vendored in
//! `proto/`, see there), for `ferritor-csi-provider`. Requires `protoc` on
//! PATH (or set `PROTOC`), like `ferritor-core`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    tonic_prost_build::configure().compile_protos(&["proto/v1alpha1/service.proto"], &["proto"])?;
    Ok(())
}
