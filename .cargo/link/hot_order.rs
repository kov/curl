// Included by the build scripts of curl-sys-abi and curl-tool: mark the
// release link of the library or the tool for `.cargo/link/cc`, which lays
// out the functions `list` names first (hot_order.py). `link_arg` is the
// build-script instruction that reaches that link
// (`rustc-cdylib-link-arg=`, `rustc-link-arg-bin=curl=`); cargo gives the
// binary's unit tests its link arguments too, and the wrapper links those
// as before.
//
// Linux only, where `.cargo/config.toml` names the wrapper. A release link
// the wrapper does not run (another linker configured) is said as a
// warning. `CURL_HOT_ORDER=off` links unordered, for measuring the order
// against none.
fn hot_order(list: &str, link_arg: &str) {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let list = std::path::Path::new(&manifest).join(list);
    let link = std::path::Path::new(&manifest).join("../../.cargo/link");
    println!("cargo::rerun-if-changed={}", list.display());
    println!("cargo::rerun-if-changed={}", link.join("cc").display());
    println!(
        "cargo::rerun-if-changed={}",
        link.join("hot_order.py").display()
    );
    println!("cargo::rerun-if-env-changed=CURL_HOT_ORDER");
    println!("cargo::rerun-if-env-changed=RUSTC_LINKER");
    if std::env::var("PROFILE").as_deref() != Ok("release")
        || std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || std::env::var("CURL_HOT_ORDER").as_deref() == Ok("off")
    {
        return;
    }
    let wrapper = std::fs::canonicalize(link.join("cc")).expect(".cargo/link/cc exists");
    let linker = std::env::var_os("RUSTC_LINKER").and_then(|l| std::fs::canonicalize(l).ok());
    let flags = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let flagged = flags.split('\x1f').any(|f| f.contains("linker="));
    if linker.as_deref() != Some(wrapper.as_path()) || flagged {
        println!(
            "cargo::warning=the release link is not .cargo/link/cc's: the hot functions \
             are not laid out first"
        );
        return;
    }
    println!("cargo::{link_arg}--curl-hot-order={}", list.display());
}
