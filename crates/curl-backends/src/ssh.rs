//! The SSH library the build has, as C's configure chooses one: libssh
//! (`CURL_USE_LIBSSH`) or libssh2 (`CURL_USE_LIBSSH2`).

use curl_core::ssh::SshLibrary;

#[cfg(all(feature = "libssh", feature = "libssh2"))]
compile_error!("one SSH library: the `libssh` or the `libssh2` feature, not both");
#[cfg(not(any(feature = "libssh", feature = "libssh2")))]
compile_error!("an SSH library is needed: the `libssh` or the `libssh2` feature");

/// The library SCP and SFTP go through.
#[cfg(feature = "libssh")]
pub const LIBRARY: SshLibrary = SshLibrary::Libssh(&curl_libssh::LIBSSH);
#[cfg(feature = "libssh2")]
pub const LIBRARY: SshLibrary = SshLibrary::Libssh2(&curl_libssh2::LIBSSH2);

/// Its name, as curl's version gives it before its version.
#[cfg(feature = "libssh")]
pub const NAME: &str = "libssh";
#[cfg(feature = "libssh2")]
pub const NAME: &str = "libssh2";

/// Its version, as curl's version gives it after its name.
#[cfg(feature = "libssh")]
pub use curl_libssh::version;
#[cfg(feature = "libssh2")]
pub use curl_libssh2::version;
