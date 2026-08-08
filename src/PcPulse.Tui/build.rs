fn main() {
    println!("cargo:rerun-if-changed=../../docs/media/pcpulse.ico");
    embed_icon();
}

/// Embed docs/media/pcpulse.ico as the first icon resource (id 1) in every
/// binary of this crate (pcpulse and pcpulse-notify); winresource emits
/// `cargo:rustc-link-arg-bins`, so all [[bin]] targets link the resource.
#[cfg(windows)]
fn embed_icon() {
    winresource::WindowsResource::new()
        .set_icon("../../docs/media/pcpulse.ico")
        .compile()
        .expect("failed to embed pcpulse.ico icon resource");
}

#[cfg(not(windows))]
fn embed_icon() {}
