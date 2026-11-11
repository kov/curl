//! What the verify callback does with the peer's leaf before it weighs
//! the flags (`mbed_verify_cb`): its text in the verbose output
//! (`mbed_dump_cert_info`), and the chain for `CURLINFO_CERTINFO`
//! (`mbed_extract_certinfo`); and the pinned public key, after the
//! handshake (`mbed_connect_step2`).

use curl_core::error::ErrorKind;
use curl_core::report::CertInfo;
use curl_core::tls::pin::{PinAsk, Pinned};
use curl_core::tls::{Text, TlsCx};

use crate::library::{Chain, KeyCopy, Mbedtls};

/// The most certificates C reports (`MAX_ALLOWED_CERT_AMOUNT`).
const MOST_CERTS: usize = 100;

/// The leaf as the library writes it out, each line of it a line of the
/// verbose output, empty lines among them (`mbed_dump_cert_info`).
pub(crate) fn dump(io: &mut TlsCx<'_>, chain: &dyn Chain) {
    let Some(text) = chain.info() else {
        io.info(format_args!("Unable to dump certificate information"));
        return;
    };
    io.info(format_args!("Server certificate:"));
    let text = text.split(|&b| b == 0).next().unwrap_or_default();
    let mut at = 0;
    while at < text.len() {
        let len = text[at..]
            .iter()
            .position(|&b| b == b'\n')
            .unwrap_or(text.len() - at);
        io.info(format_args!("{}", Text(&text[at..at + len])));
        at += len;
        if at < text.len() {
            at += 1;
        }
    }
}

/// The chain from the leaf on reported, unless it has more certificates
/// than C reports (`mbed_extract_certinfo`). What it is short of, room or
/// a certificate that reads, ends the report there, as C's does, but not
/// the handshake.
pub(crate) fn certinfo(io: &mut TlsCx<'_>, chain: &dyn Chain) {
    let Ok(ders) = chain.ders(MOST_CERTS + 1) else {
        return;
    };
    if ders.len() > MOST_CERTS {
        io.info(format_args!(
            "More certificates than allowed ({MOST_CERTS}), skipping certinfo"
        ));
        return;
    }
    let Ok(mut info) = CertInfo::new(ders.len()) else {
        return;
    };
    for (i, der) in ders.iter().enumerate() {
        if curl_core::tls::x509::certinfo(io, &mut info, i, der).is_err() {
            break;
        }
    }
    // C's report is made as the callback goes and fails it nowhere
    // (`mbed_extract_certinfo` returns nothing): out of memory, the
    // handshake goes on without it.
    let _unreported: Result<(), ErrorKind> = io.set_certinfo(Some(info));
}

/// The peer's public key is the one `ask` pins (`mbed_connect_step2`):
/// the key of the certificate it showed, said why if not.
pub(crate) fn pinned_key<G: Mbedtls>(
    lib: &G,
    io: &mut TlsCx<'_>,
    peer: Option<&[u8]>,
    ask: PinAsk,
) -> Result<Pinned, ErrorKind> {
    let Some(der) = peer else {
        return Err(io.fail(
            ErrorKind::SslPinnedpubkeynotmatch,
            format_args!("Failed due to missing peer certificate"),
        ));
    };
    let key = match lib.public_key(der) {
        Ok(key) => key,
        Err(KeyCopy::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
        Err(KeyCopy::Certificate) => {
            return Err(io.fail(
                ErrorKind::SslPinnedpubkeynotmatch,
                format_args!("Failed copying peer certificate"),
            ));
        }
        Err(KeyCopy::Key) => {
            return Err(io.fail(
                ErrorKind::SslPinnedpubkeynotmatch,
                format_args!("Failed copying public key from peer certificate"),
            ));
        }
    };
    ask.check(io, &key)
}
