//! Decide where the library looks for certificates to trust when a
//! transfer names none, as CMake decides it.

fn main() {
    curl_build::write_ca_defaults();
}
