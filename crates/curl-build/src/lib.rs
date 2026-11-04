//! What the library crates' build scripts share: where a C library is,
//! from pkg-config, and whether it has a function, as the C build's
//! CMake finds and checks them. Build scripts only: aborting on a failed
//! allocation is fine here.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::path::PathBuf;
use std::process::Command;

/// Whether the target's C is MSVC's, which finds vcpkg's libraries
/// through its own environment and asks pkg-config nothing.
fn msvc() -> bool {
    std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|e| e == "msvc")
}

/// pkg-config's words for `package` under `flag`, or none where it does
/// not know the package, is not installed, or the target is MSVC's.
pub fn pkg_config(package: &str, flag: &str) -> Option<Vec<String>> {
    if msvc() {
        return None;
    }
    let out = Command::new("pkg-config")
        .args([flag, package])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).expect("pkg-config's output is text");
    Some(text.split_whitespace().map(str::to_owned).collect())
}

/// Links `lib`, from where pkg-config's `package` says it is when that
/// is outside the linker's own paths (Homebrew's on macOS), as CMake's
/// find modules take it.
pub fn link(lib: &str, package: &str) {
    println!("cargo::rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo::rerun-if-env-changed=PKG_CONFIG_LIBDIR");
    println!("cargo::rustc-link-lib={lib}");
    for dir in library_dirs(package) {
        println!("cargo::rustc-link-search=native={}", dir.display());
    }
}

/// The directories pkg-config's `package` names for its libraries.
pub fn library_dirs(package: &str) -> Vec<PathBuf> {
    pkg_config(package, "--libs-only-L")
        .unwrap_or_default()
        .iter()
        .filter_map(|w| w.strip_prefix("-L"))
        .map(PathBuf::from)
        .collect()
}

/// The directories pkg-config's `package` names for its headers.
pub fn include_dirs(package: &str) -> Vec<PathBuf> {
    pkg_config(package, "--cflags-only-I")
        .unwrap_or_default()
        .iter()
        .filter_map(|w| w.strip_prefix("-I"))
        .map(PathBuf::from)
        .collect()
}

/// What the build's LDAP library, libldap and liblber from where
/// pkg-config finds them (the system's otherwise, as macOS's), can do,
/// as CMake's `check_function_exists` decides it. The LDAP crate links
/// it, and the core lists the LDAP protocols, by this one answer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LdapLibrary {
    /// It links, with `ldap_init`: C's build has LDAP.
    pub links: bool,
    /// It has `ldap_init_fd`: C's build takes `lib/openldap.c`
    /// (`USE_OPENLDAP`), `lib/ldap.c` otherwise.
    pub init_fd: bool,
}

/// The build's LDAP library, as [`LdapLibrary`] says.
pub fn ldap() -> LdapLibrary {
    println!("cargo::rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo::rerun-if-env-changed=PKG_CONFIG_LIBDIR");
    let mut libs: Vec<String> = ["ldap", "lber"]
        .iter()
        .flat_map(|package| library_dirs(package))
        .map(|dir| format!("-L{}", dir.display()))
        .collect();
    libs.extend(["-lldap".to_owned(), "-llber".to_owned()]);
    let links = function_exists("ldap_init", "ldap_init", &libs);
    LdapLibrary {
        links,
        init_fd: links && function_exists("ldap_init_fd", "ldap_init_fd", &libs),
    }
}

/// Whether a program calling `function` links with `libs` (linker
/// words: `-L`, `-l`, `-framework`), as CMake's `check_function_exists`
/// decides it. `name` names the program in the build's output directory.
pub fn function_exists(name: &str, function: &str, libs: &[String]) -> bool {
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    let src = out.join(format!("{name}.c"));
    // CMake's CheckFunctionExists.c: declared with no prototype, so any
    // signature links.
    std::fs::write(
        &src,
        format!("char {function}(void);\nint main(void) {{ return (int){function}(); }}\n"),
    )
    .expect("the build's output directory is writable");
    let compiler = cc::Build::new()
        .cargo_metadata(false)
        .cargo_warnings(false)
        .get_compiler();
    let mut cmd = compiler.to_command();
    if compiler.is_like_msvc() {
        cmd.arg(&src)
            .arg(format!("/Fe{}", out.join(name).display()))
            .arg(format!("/Fo{}", out.join(format!("{name}.obj")).display()))
            .arg("/link")
            .args(libs);
    } else {
        cmd.arg(&src).arg("-o").arg(out.join(name)).args(libs);
    }
    cmd.output().is_ok_and(|o| o.status.success())
}
