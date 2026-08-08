fn main() {
    println!("cargo:rerun-if-changed=../../docs/media/pcpulse.ico");
    embed_icon();
}

/// Embed docs/media/pcpulse.ico as the first icon resource (id 1) in the
/// pcpulse-collector binary via `cargo:rustc-link-arg-bins`.
#[cfg(windows)]
fn embed_icon() {
    winresource::WindowsResource::new()
        .set_icon("../../docs/media/pcpulse.ico")
        .compile()
        .expect("failed to embed pcpulse.ico icon resource");
}

#[cfg(not(windows))]
fn embed_icon() {}
