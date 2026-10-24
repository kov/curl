//! The names C gives what OpenSSL reports, for the trace and the failure
//! texts: protocol versions, record and message types (`ossl_trace`), and
//! `SSL_get_error`'s answers (`SSL_ERROR_to_str`).

use core::ffi::c_int;
use core::fmt;

/// A protocol version as `ossl_trace` names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Version(pub(crate) c_int);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0x300 => f.write_str("SSLv3"),
            0x301 => f.write_str("TLSv1.0"),
            0x302 => f.write_str("TLSv1.1"),
            0x303 => f.write_str("TLSv1.2"),
            0x304 => f.write_str("TLSv1.3"),
            // As C's "(%x)" prints it, for an `unsigned int`.
            v => write!(f, "({:x})", v as u32),
        }
    }
}

/// `SSL3_RT_CHANGE_CIPHER_SPEC`, `SSL3_RT_ALERT`, `SSL3_RT_HANDSHAKE`,
/// `SSL3_RT_APPLICATION_DATA`.
pub(crate) const CHANGE_CIPHER_SPEC: c_int = 20;
pub(crate) const ALERT: c_int = 21;
pub(crate) const HANDSHAKE: c_int = 22;
pub(crate) const APPLICATION_DATA: c_int = 23;
/// `SSL3_RT_HEADER`: a record's header, which C does not name.
pub(crate) const HEADER: c_int = 0x100;
/// `SSL3_RT_INNER_CONTENT_TYPE`: TLS 1.3's inner type, likewise.
pub(crate) const INNER_CONTENT_TYPE: c_int = 0x101;

/// A record type as `tls_rt_type` names it.
pub(crate) fn record_type(content_type: c_int) -> &'static str {
    match content_type {
        HEADER => "TLS header",
        CHANGE_CIPHER_SPEC => "TLS change cipher",
        ALERT => "TLS alert",
        HANDSHAKE => "TLS handshake",
        APPLICATION_DATA => "TLS app data",
        _ => "TLS Unknown",
    }
}

/// A handshake message type as `ssl_msg_type` names it, for the major
/// version `major` (only SSLv3's and TLS's are named).
pub(crate) fn message_type(major: c_int, msg: c_int) -> &'static str {
    if major != 3 {
        return "Unknown";
    }
    match msg {
        0 => "Hello request",
        1 => "Client hello",
        2 => "Server hello",
        4 => "Newsession Ticket",
        11 => "Certificate",
        12 => "Server key exchange",
        16 => "Client key exchange",
        13 => "Request CERT",
        14 => "Server finished",
        15 => "CERT verify",
        20 => "Finished",
        22 => "Certificate Status",
        8 => "Encrypted Extensions",
        23 => "Supplemental data",
        5 => "End of early data",
        24 => "Key update",
        67 => "Next protocol",
        254 => "Message hash",
        _ => "Unknown",
    }
}

/// `SSL_get_error`'s answer as `SSL_ERROR_to_str` names it.
pub(crate) fn ssl_error(err: c_int) -> &'static str {
    match err {
        0 => "SSL_ERROR_NONE",
        1 => "SSL_ERROR_SSL",
        2 => "SSL_ERROR_WANT_READ",
        3 => "SSL_ERROR_WANT_WRITE",
        4 => "SSL_ERROR_WANT_X509_LOOKUP",
        5 => "SSL_ERROR_SYSCALL",
        6 => "SSL_ERROR_ZERO_RETURN",
        7 => "SSL_ERROR_WANT_CONNECT",
        8 => "SSL_ERROR_WANT_ACCEPT",
        9 => "SSL_ERROR_WANT_ASYNC",
        10 => "SSL_ERROR_WANT_ASYNC_JOB",
        11 => "SSL_ERROR_WANT_CLIENT_HELLO_CB",
        _ => "SSL_ERROR unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names are C's, the numbers OpenSSL 3's headers'.
    #[test]
    fn names_are_c_s() {
        assert_eq!(format!("{}", Version(0x304)), "TLSv1.3");
        assert_eq!(format!("{}", Version(0x303)), "TLSv1.2");
        assert_eq!(format!("{}", Version(0xfefd)), "(fefd)");
        assert_eq!(record_type(22), "TLS handshake");
        assert_eq!(record_type(0x100), "TLS header");
        assert_eq!(record_type(99), "TLS Unknown");
        assert_eq!(message_type(3, 1), "Client hello");
        assert_eq!(message_type(3, 4), "Newsession Ticket");
        assert_eq!(message_type(3, 15), "CERT verify");
        assert_eq!(message_type(2, 1), "Unknown");
        assert_eq!(ssl_error(5), "SSL_ERROR_SYSCALL");
        assert_eq!(ssl_error(12), "SSL_ERROR unknown");
    }
}
