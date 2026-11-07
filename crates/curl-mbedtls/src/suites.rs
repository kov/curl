//! The names of TLS cipher suites, OpenSSL's and IANA's, and their
//! numbers (`lib/vtls/cipher_suite.c`), for a library that takes a list
//! of numbers where the transfer gives one of names
//! (`CURLOPT_SSL_CIPHER_LIST`, `CURLOPT_TLS13_CIPHERS`): mbedTLS. The
//! table is C's for an mbedTLS build, each name as its parts.

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::error::ErrorKind;
use curl_core::tls::{Text, TlsCx};

use crate::library::Mbedtls;

/// Each suite C knows, by number, once by its IANA name (its first part
/// `TLS`, joined by `_`) and, where OpenSSL names it, once by OpenSSL's
/// (joined by `-`), in C's order.
const SUITES: &[(u16, &[&str])] = &[
    (0x1301, &["TLS", "AES", "128", "GCM", "SHA256"]),
    (0x1302, &["TLS", "AES", "256", "GCM", "SHA384"]),
    (0x1303, &["TLS", "CHACHA20", "POLY1305", "SHA256"]),
    (0x1304, &["TLS", "AES", "128", "CCM", "SHA256"]),
    (0x1305, &["TLS", "AES", "128", "CCM", "8", "SHA256"]),
    (
        0xC02B,
        &[
            "TLS", "ECDHE", "ECDSA", "WITH", "AES", "128", "GCM", "SHA256",
        ],
    ),
    (0xC02B, &["ECDHE", "ECDSA", "AES128", "GCM", "SHA256"]),
    (
        0xC02C,
        &[
            "TLS", "ECDHE", "ECDSA", "WITH", "AES", "256", "GCM", "SHA384",
        ],
    ),
    (0xC02C, &["ECDHE", "ECDSA", "AES256", "GCM", "SHA384"]),
    (
        0xC02F,
        &["TLS", "ECDHE", "RSA", "WITH", "AES", "128", "GCM", "SHA256"],
    ),
    (0xC02F, &["ECDHE", "RSA", "AES128", "GCM", "SHA256"]),
    (
        0xC030,
        &["TLS", "ECDHE", "RSA", "WITH", "AES", "256", "GCM", "SHA384"],
    ),
    (0xC030, &["ECDHE", "RSA", "AES256", "GCM", "SHA384"]),
    (
        0xCCA8,
        &[
            "TLS", "ECDHE", "RSA", "WITH", "CHACHA20", "POLY1305", "SHA256",
        ],
    ),
    (0xCCA8, &["ECDHE", "RSA", "CHACHA20", "POLY1305"]),
    (
        0xCCA9,
        &[
            "TLS", "ECDHE", "ECDSA", "WITH", "CHACHA20", "POLY1305", "SHA256",
        ],
    ),
    (0xCCA9, &["ECDHE", "ECDSA", "CHACHA20", "POLY1305"]),
    (0x002F, &["TLS", "RSA", "WITH", "AES", "128", "CBC", "SHA"]),
    (0x002F, &["AES128", "SHA"]),
    (0x0035, &["TLS", "RSA", "WITH", "AES", "256", "CBC", "SHA"]),
    (0x0035, &["AES256", "SHA"]),
    (
        0x003C,
        &["TLS", "RSA", "WITH", "AES", "128", "CBC", "SHA256"],
    ),
    (0x003C, &["AES128", "SHA256"]),
    (
        0x003D,
        &["TLS", "RSA", "WITH", "AES", "256", "CBC", "SHA256"],
    ),
    (0x003D, &["AES256", "SHA256"]),
    (
        0x009C,
        &["TLS", "RSA", "WITH", "AES", "128", "GCM", "SHA256"],
    ),
    (0x009C, &["AES128", "GCM", "SHA256"]),
    (
        0x009D,
        &["TLS", "RSA", "WITH", "AES", "256", "GCM", "SHA384"],
    ),
    (0x009D, &["AES256", "GCM", "SHA384"]),
    (
        0xC004,
        &["TLS", "ECDH", "ECDSA", "WITH", "AES", "128", "CBC", "SHA"],
    ),
    (0xC004, &["ECDH", "ECDSA", "AES128", "SHA"]),
    (
        0xC005,
        &["TLS", "ECDH", "ECDSA", "WITH", "AES", "256", "CBC", "SHA"],
    ),
    (0xC005, &["ECDH", "ECDSA", "AES256", "SHA"]),
    (
        0xC009,
        &["TLS", "ECDHE", "ECDSA", "WITH", "AES", "128", "CBC", "SHA"],
    ),
    (0xC009, &["ECDHE", "ECDSA", "AES128", "SHA"]),
    (
        0xC00A,
        &["TLS", "ECDHE", "ECDSA", "WITH", "AES", "256", "CBC", "SHA"],
    ),
    (0xC00A, &["ECDHE", "ECDSA", "AES256", "SHA"]),
    (
        0xC00E,
        &["TLS", "ECDH", "RSA", "WITH", "AES", "128", "CBC", "SHA"],
    ),
    (0xC00E, &["ECDH", "RSA", "AES128", "SHA"]),
    (
        0xC00F,
        &["TLS", "ECDH", "RSA", "WITH", "AES", "256", "CBC", "SHA"],
    ),
    (0xC00F, &["ECDH", "RSA", "AES256", "SHA"]),
    (
        0xC013,
        &["TLS", "ECDHE", "RSA", "WITH", "AES", "128", "CBC", "SHA"],
    ),
    (0xC013, &["ECDHE", "RSA", "AES128", "SHA"]),
    (
        0xC014,
        &["TLS", "ECDHE", "RSA", "WITH", "AES", "256", "CBC", "SHA"],
    ),
    (0xC014, &["ECDHE", "RSA", "AES256", "SHA"]),
    (
        0xC023,
        &[
            "TLS", "ECDHE", "ECDSA", "WITH", "AES", "128", "CBC", "SHA256",
        ],
    ),
    (0xC023, &["ECDHE", "ECDSA", "AES128", "SHA256"]),
    (
        0xC024,
        &[
            "TLS", "ECDHE", "ECDSA", "WITH", "AES", "256", "CBC", "SHA384",
        ],
    ),
    (0xC024, &["ECDHE", "ECDSA", "AES256", "SHA384"]),
    (
        0xC025,
        &[
            "TLS", "ECDH", "ECDSA", "WITH", "AES", "128", "CBC", "SHA256",
        ],
    ),
    (0xC025, &["ECDH", "ECDSA", "AES128", "SHA256"]),
    (
        0xC026,
        &[
            "TLS", "ECDH", "ECDSA", "WITH", "AES", "256", "CBC", "SHA384",
        ],
    ),
    (0xC026, &["ECDH", "ECDSA", "AES256", "SHA384"]),
    (
        0xC027,
        &["TLS", "ECDHE", "RSA", "WITH", "AES", "128", "CBC", "SHA256"],
    ),
    (0xC027, &["ECDHE", "RSA", "AES128", "SHA256"]),
    (
        0xC028,
        &["TLS", "ECDHE", "RSA", "WITH", "AES", "256", "CBC", "SHA384"],
    ),
    (0xC028, &["ECDHE", "RSA", "AES256", "SHA384"]),
    (
        0xC029,
        &["TLS", "ECDH", "RSA", "WITH", "AES", "128", "CBC", "SHA256"],
    ),
    (0xC029, &["ECDH", "RSA", "AES128", "SHA256"]),
    (
        0xC02A,
        &["TLS", "ECDH", "RSA", "WITH", "AES", "256", "CBC", "SHA384"],
    ),
    (0xC02A, &["ECDH", "RSA", "AES256", "SHA384"]),
    (
        0xC02D,
        &[
            "TLS", "ECDH", "ECDSA", "WITH", "AES", "128", "GCM", "SHA256",
        ],
    ),
    (0xC02D, &["ECDH", "ECDSA", "AES128", "GCM", "SHA256"]),
    (
        0xC02E,
        &[
            "TLS", "ECDH", "ECDSA", "WITH", "AES", "256", "GCM", "SHA384",
        ],
    ),
    (0xC02E, &["ECDH", "ECDSA", "AES256", "GCM", "SHA384"]),
    (
        0xC031,
        &["TLS", "ECDH", "RSA", "WITH", "AES", "128", "GCM", "SHA256"],
    ),
    (0xC031, &["ECDH", "RSA", "AES128", "GCM", "SHA256"]),
    (
        0xC032,
        &["TLS", "ECDH", "RSA", "WITH", "AES", "256", "GCM", "SHA384"],
    ),
    (0xC032, &["ECDH", "RSA", "AES256", "GCM", "SHA384"]),
    (0x0001, &["TLS", "RSA", "WITH", "NULL", "MD5"]),
    (0x0001, &["NULL", "MD5"]),
    (0x0002, &["TLS", "RSA", "WITH", "NULL", "SHA"]),
    (0x0002, &["NULL", "SHA"]),
    (0x002C, &["TLS", "PSK", "WITH", "NULL", "SHA"]),
    (0x002C, &["PSK", "NULL", "SHA"]),
    (0x002D, &["TLS", "DHE", "PSK", "WITH", "NULL", "SHA"]),
    (0x002D, &["DHE", "PSK", "NULL", "SHA"]),
    (0x002E, &["TLS", "RSA", "PSK", "WITH", "NULL", "SHA"]),
    (0x002E, &["RSA", "PSK", "NULL", "SHA"]),
    (
        0x0033,
        &["TLS", "DHE", "RSA", "WITH", "AES", "128", "CBC", "SHA"],
    ),
    (0x0033, &["DHE", "RSA", "AES128", "SHA"]),
    (
        0x0039,
        &["TLS", "DHE", "RSA", "WITH", "AES", "256", "CBC", "SHA"],
    ),
    (0x0039, &["DHE", "RSA", "AES256", "SHA"]),
    (0x003B, &["TLS", "RSA", "WITH", "NULL", "SHA256"]),
    (0x003B, &["NULL", "SHA256"]),
    (
        0x0067,
        &["TLS", "DHE", "RSA", "WITH", "AES", "128", "CBC", "SHA256"],
    ),
    (0x0067, &["DHE", "RSA", "AES128", "SHA256"]),
    (
        0x006B,
        &["TLS", "DHE", "RSA", "WITH", "AES", "256", "CBC", "SHA256"],
    ),
    (0x006B, &["DHE", "RSA", "AES256", "SHA256"]),
    (0x008C, &["TLS", "PSK", "WITH", "AES", "128", "CBC", "SHA"]),
    (0x008C, &["PSK", "AES128", "CBC", "SHA"]),
    (0x008D, &["TLS", "PSK", "WITH", "AES", "256", "CBC", "SHA"]),
    (0x008D, &["PSK", "AES256", "CBC", "SHA"]),
    (
        0x0090,
        &["TLS", "DHE", "PSK", "WITH", "AES", "128", "CBC", "SHA"],
    ),
    (0x0090, &["DHE", "PSK", "AES128", "CBC", "SHA"]),
    (
        0x0091,
        &["TLS", "DHE", "PSK", "WITH", "AES", "256", "CBC", "SHA"],
    ),
    (0x0091, &["DHE", "PSK", "AES256", "CBC", "SHA"]),
    (
        0x0094,
        &["TLS", "RSA", "PSK", "WITH", "AES", "128", "CBC", "SHA"],
    ),
    (0x0094, &["RSA", "PSK", "AES128", "CBC", "SHA"]),
    (
        0x0095,
        &["TLS", "RSA", "PSK", "WITH", "AES", "256", "CBC", "SHA"],
    ),
    (0x0095, &["RSA", "PSK", "AES256", "CBC", "SHA"]),
    (
        0x009E,
        &["TLS", "DHE", "RSA", "WITH", "AES", "128", "GCM", "SHA256"],
    ),
    (0x009E, &["DHE", "RSA", "AES128", "GCM", "SHA256"]),
    (
        0x009F,
        &["TLS", "DHE", "RSA", "WITH", "AES", "256", "GCM", "SHA384"],
    ),
    (0x009F, &["DHE", "RSA", "AES256", "GCM", "SHA384"]),
    (
        0x00A8,
        &["TLS", "PSK", "WITH", "AES", "128", "GCM", "SHA256"],
    ),
    (0x00A8, &["PSK", "AES128", "GCM", "SHA256"]),
    (
        0x00A9,
        &["TLS", "PSK", "WITH", "AES", "256", "GCM", "SHA384"],
    ),
    (0x00A9, &["PSK", "AES256", "GCM", "SHA384"]),
    (
        0x00AA,
        &["TLS", "DHE", "PSK", "WITH", "AES", "128", "GCM", "SHA256"],
    ),
    (0x00AA, &["DHE", "PSK", "AES128", "GCM", "SHA256"]),
    (
        0x00AB,
        &["TLS", "DHE", "PSK", "WITH", "AES", "256", "GCM", "SHA384"],
    ),
    (0x00AB, &["DHE", "PSK", "AES256", "GCM", "SHA384"]),
    (
        0x00AC,
        &["TLS", "RSA", "PSK", "WITH", "AES", "128", "GCM", "SHA256"],
    ),
    (0x00AC, &["RSA", "PSK", "AES128", "GCM", "SHA256"]),
    (
        0x00AD,
        &["TLS", "RSA", "PSK", "WITH", "AES", "256", "GCM", "SHA384"],
    ),
    (0x00AD, &["RSA", "PSK", "AES256", "GCM", "SHA384"]),
    (
        0x00AE,
        &["TLS", "PSK", "WITH", "AES", "128", "CBC", "SHA256"],
    ),
    (0x00AE, &["PSK", "AES128", "CBC", "SHA256"]),
    (
        0x00AF,
        &["TLS", "PSK", "WITH", "AES", "256", "CBC", "SHA384"],
    ),
    (0x00AF, &["PSK", "AES256", "CBC", "SHA384"]),
    (0x00B0, &["TLS", "PSK", "WITH", "NULL", "SHA256"]),
    (0x00B0, &["PSK", "NULL", "SHA256"]),
    (0x00B1, &["TLS", "PSK", "WITH", "NULL", "SHA384"]),
    (0x00B1, &["PSK", "NULL", "SHA384"]),
    (
        0x00B2,
        &["TLS", "DHE", "PSK", "WITH", "AES", "128", "CBC", "SHA256"],
    ),
    (0x00B2, &["DHE", "PSK", "AES128", "CBC", "SHA256"]),
    (
        0x00B3,
        &["TLS", "DHE", "PSK", "WITH", "AES", "256", "CBC", "SHA384"],
    ),
    (0x00B3, &["DHE", "PSK", "AES256", "CBC", "SHA384"]),
    (0x00B4, &["TLS", "DHE", "PSK", "WITH", "NULL", "SHA256"]),
    (0x00B4, &["DHE", "PSK", "NULL", "SHA256"]),
    (0x00B5, &["TLS", "DHE", "PSK", "WITH", "NULL", "SHA384"]),
    (0x00B5, &["DHE", "PSK", "NULL", "SHA384"]),
    (
        0x00B6,
        &["TLS", "RSA", "PSK", "WITH", "AES", "128", "CBC", "SHA256"],
    ),
    (0x00B6, &["RSA", "PSK", "AES128", "CBC", "SHA256"]),
    (
        0x00B7,
        &["TLS", "RSA", "PSK", "WITH", "AES", "256", "CBC", "SHA384"],
    ),
    (0x00B7, &["RSA", "PSK", "AES256", "CBC", "SHA384"]),
    (0x00B8, &["TLS", "RSA", "PSK", "WITH", "NULL", "SHA256"]),
    (0x00B8, &["RSA", "PSK", "NULL", "SHA256"]),
    (0x00B9, &["TLS", "RSA", "PSK", "WITH", "NULL", "SHA384"]),
    (0x00B9, &["RSA", "PSK", "NULL", "SHA384"]),
    (0xC001, &["TLS", "ECDH", "ECDSA", "WITH", "NULL", "SHA"]),
    (0xC001, &["ECDH", "ECDSA", "NULL", "SHA"]),
    (0xC006, &["TLS", "ECDHE", "ECDSA", "WITH", "NULL", "SHA"]),
    (0xC006, &["ECDHE", "ECDSA", "NULL", "SHA"]),
    (0xC00B, &["TLS", "ECDH", "RSA", "WITH", "NULL", "SHA"]),
    (0xC00B, &["ECDH", "RSA", "NULL", "SHA"]),
    (0xC010, &["TLS", "ECDHE", "RSA", "WITH", "NULL", "SHA"]),
    (0xC010, &["ECDHE", "RSA", "NULL", "SHA"]),
    (
        0xC035,
        &["TLS", "ECDHE", "PSK", "WITH", "AES", "128", "CBC", "SHA"],
    ),
    (0xC035, &["ECDHE", "PSK", "AES128", "CBC", "SHA"]),
    (
        0xC036,
        &["TLS", "ECDHE", "PSK", "WITH", "AES", "256", "CBC", "SHA"],
    ),
    (0xC036, &["ECDHE", "PSK", "AES256", "CBC", "SHA"]),
    (
        0xCCAB,
        &["TLS", "PSK", "WITH", "CHACHA20", "POLY1305", "SHA256"],
    ),
    (0xCCAB, &["PSK", "CHACHA20", "POLY1305"]),
    (0xC09C, &["TLS", "RSA", "WITH", "AES", "128", "CCM"]),
    (0xC09C, &["AES128", "CCM"]),
    (0xC09D, &["TLS", "RSA", "WITH", "AES", "256", "CCM"]),
    (0xC09D, &["AES256", "CCM"]),
    (0xC0A0, &["TLS", "RSA", "WITH", "AES", "128", "CCM", "8"]),
    (0xC0A0, &["AES128", "CCM8"]),
    (0xC0A1, &["TLS", "RSA", "WITH", "AES", "256", "CCM", "8"]),
    (0xC0A1, &["AES256", "CCM8"]),
    (
        0xC0AC,
        &["TLS", "ECDHE", "ECDSA", "WITH", "AES", "128", "CCM"],
    ),
    (0xC0AC, &["ECDHE", "ECDSA", "AES128", "CCM"]),
    (
        0xC0AD,
        &["TLS", "ECDHE", "ECDSA", "WITH", "AES", "256", "CCM"],
    ),
    (0xC0AD, &["ECDHE", "ECDSA", "AES256", "CCM"]),
    (
        0xC0AE,
        &["TLS", "ECDHE", "ECDSA", "WITH", "AES", "128", "CCM", "8"],
    ),
    (0xC0AE, &["ECDHE", "ECDSA", "AES128", "CCM8"]),
    (
        0xC0AF,
        &["TLS", "ECDHE", "ECDSA", "WITH", "AES", "256", "CCM", "8"],
    ),
    (0xC0AF, &["ECDHE", "ECDSA", "AES256", "CCM8"]),
    (
        0x0041,
        &["TLS", "RSA", "WITH", "CAMELLIA", "128", "CBC", "SHA"],
    ),
    (0x0041, &["CAMELLIA128", "SHA"]),
    (
        0x0045,
        &["TLS", "DHE", "RSA", "WITH", "CAMELLIA", "128", "CBC", "SHA"],
    ),
    (0x0045, &["DHE", "RSA", "CAMELLIA128", "SHA"]),
    (
        0x0084,
        &["TLS", "RSA", "WITH", "CAMELLIA", "256", "CBC", "SHA"],
    ),
    (0x0084, &["CAMELLIA256", "SHA"]),
    (
        0x0088,
        &["TLS", "DHE", "RSA", "WITH", "CAMELLIA", "256", "CBC", "SHA"],
    ),
    (0x0088, &["DHE", "RSA", "CAMELLIA256", "SHA"]),
    (
        0x00BA,
        &["TLS", "RSA", "WITH", "CAMELLIA", "128", "CBC", "SHA256"],
    ),
    (0x00BA, &["CAMELLIA128", "SHA256"]),
    (
        0x00BE,
        &[
            "TLS", "DHE", "RSA", "WITH", "CAMELLIA", "128", "CBC", "SHA256",
        ],
    ),
    (0x00BE, &["DHE", "RSA", "CAMELLIA128", "SHA256"]),
    (
        0x00C0,
        &["TLS", "RSA", "WITH", "CAMELLIA", "256", "CBC", "SHA256"],
    ),
    (0x00C0, &["CAMELLIA256", "SHA256"]),
    (
        0x00C4,
        &[
            "TLS", "DHE", "RSA", "WITH", "CAMELLIA", "256", "CBC", "SHA256",
        ],
    ),
    (0x00C4, &["DHE", "RSA", "CAMELLIA256", "SHA256"]),
    (
        0xC037,
        &["TLS", "ECDHE", "PSK", "WITH", "AES", "128", "CBC", "SHA256"],
    ),
    (0xC037, &["ECDHE", "PSK", "AES128", "CBC", "SHA256"]),
    (
        0xC038,
        &["TLS", "ECDHE", "PSK", "WITH", "AES", "256", "CBC", "SHA384"],
    ),
    (0xC038, &["ECDHE", "PSK", "AES256", "CBC", "SHA384"]),
    (0xC039, &["TLS", "ECDHE", "PSK", "WITH", "NULL", "SHA"]),
    (0xC039, &["ECDHE", "PSK", "NULL", "SHA"]),
    (0xC03A, &["TLS", "ECDHE", "PSK", "WITH", "NULL", "SHA256"]),
    (0xC03A, &["ECDHE", "PSK", "NULL", "SHA256"]),
    (0xC03B, &["TLS", "ECDHE", "PSK", "WITH", "NULL", "SHA384"]),
    (0xC03B, &["ECDHE", "PSK", "NULL", "SHA384"]),
    (
        0xC03C,
        &["TLS", "RSA", "WITH", "ARIA", "128", "CBC", "SHA256"],
    ),
    (0xC03C, &["ARIA128", "SHA256"]),
    (
        0xC03D,
        &["TLS", "RSA", "WITH", "ARIA", "256", "CBC", "SHA384"],
    ),
    (0xC03D, &["ARIA256", "SHA384"]),
    (
        0xC044,
        &["TLS", "DHE", "RSA", "WITH", "ARIA", "128", "CBC", "SHA256"],
    ),
    (0xC044, &["DHE", "RSA", "ARIA128", "SHA256"]),
    (
        0xC045,
        &["TLS", "DHE", "RSA", "WITH", "ARIA", "256", "CBC", "SHA384"],
    ),
    (0xC045, &["DHE", "RSA", "ARIA256", "SHA384"]),
    (
        0xC048,
        &[
            "TLS", "ECDHE", "ECDSA", "WITH", "ARIA", "128", "CBC", "SHA256",
        ],
    ),
    (0xC048, &["ECDHE", "ECDSA", "ARIA128", "SHA256"]),
    (
        0xC049,
        &[
            "TLS", "ECDHE", "ECDSA", "WITH", "ARIA", "256", "CBC", "SHA384",
        ],
    ),
    (0xC049, &["ECDHE", "ECDSA", "ARIA256", "SHA384"]),
    (
        0xC04A,
        &[
            "TLS", "ECDH", "ECDSA", "WITH", "ARIA", "128", "CBC", "SHA256",
        ],
    ),
    (0xC04A, &["ECDH", "ECDSA", "ARIA128", "SHA256"]),
    (
        0xC04B,
        &[
            "TLS", "ECDH", "ECDSA", "WITH", "ARIA", "256", "CBC", "SHA384",
        ],
    ),
    (0xC04B, &["ECDH", "ECDSA", "ARIA256", "SHA384"]),
    (
        0xC04C,
        &[
            "TLS", "ECDHE", "RSA", "WITH", "ARIA", "128", "CBC", "SHA256",
        ],
    ),
    (0xC04C, &["ECDHE", "ARIA128", "SHA256"]),
    (
        0xC04D,
        &[
            "TLS", "ECDHE", "RSA", "WITH", "ARIA", "256", "CBC", "SHA384",
        ],
    ),
    (0xC04D, &["ECDHE", "ARIA256", "SHA384"]),
    (
        0xC04E,
        &["TLS", "ECDH", "RSA", "WITH", "ARIA", "128", "CBC", "SHA256"],
    ),
    (0xC04E, &["ECDH", "ARIA128", "SHA256"]),
    (
        0xC04F,
        &["TLS", "ECDH", "RSA", "WITH", "ARIA", "256", "CBC", "SHA384"],
    ),
    (0xC04F, &["ECDH", "ARIA256", "SHA384"]),
    (
        0xC050,
        &["TLS", "RSA", "WITH", "ARIA", "128", "GCM", "SHA256"],
    ),
    (0xC050, &["ARIA128", "GCM", "SHA256"]),
    (
        0xC051,
        &["TLS", "RSA", "WITH", "ARIA", "256", "GCM", "SHA384"],
    ),
    (0xC051, &["ARIA256", "GCM", "SHA384"]),
    (
        0xC052,
        &["TLS", "DHE", "RSA", "WITH", "ARIA", "128", "GCM", "SHA256"],
    ),
    (0xC052, &["DHE", "RSA", "ARIA128", "GCM", "SHA256"]),
    (
        0xC053,
        &["TLS", "DHE", "RSA", "WITH", "ARIA", "256", "GCM", "SHA384"],
    ),
    (0xC053, &["DHE", "RSA", "ARIA256", "GCM", "SHA384"]),
    (
        0xC05C,
        &[
            "TLS", "ECDHE", "ECDSA", "WITH", "ARIA", "128", "GCM", "SHA256",
        ],
    ),
    (0xC05C, &["ECDHE", "ECDSA", "ARIA128", "GCM", "SHA256"]),
    (
        0xC05D,
        &[
            "TLS", "ECDHE", "ECDSA", "WITH", "ARIA", "256", "GCM", "SHA384",
        ],
    ),
    (0xC05D, &["ECDHE", "ECDSA", "ARIA256", "GCM", "SHA384"]),
    (
        0xC05E,
        &[
            "TLS", "ECDH", "ECDSA", "WITH", "ARIA", "128", "GCM", "SHA256",
        ],
    ),
    (0xC05E, &["ECDH", "ECDSA", "ARIA128", "GCM", "SHA256"]),
    (
        0xC05F,
        &[
            "TLS", "ECDH", "ECDSA", "WITH", "ARIA", "256", "GCM", "SHA384",
        ],
    ),
    (0xC05F, &["ECDH", "ECDSA", "ARIA256", "GCM", "SHA384"]),
    (
        0xC060,
        &[
            "TLS", "ECDHE", "RSA", "WITH", "ARIA", "128", "GCM", "SHA256",
        ],
    ),
    (0xC060, &["ECDHE", "ARIA128", "GCM", "SHA256"]),
    (
        0xC061,
        &[
            "TLS", "ECDHE", "RSA", "WITH", "ARIA", "256", "GCM", "SHA384",
        ],
    ),
    (0xC061, &["ECDHE", "ARIA256", "GCM", "SHA384"]),
    (
        0xC062,
        &["TLS", "ECDH", "RSA", "WITH", "ARIA", "128", "GCM", "SHA256"],
    ),
    (0xC062, &["ECDH", "ARIA128", "GCM", "SHA256"]),
    (
        0xC063,
        &["TLS", "ECDH", "RSA", "WITH", "ARIA", "256", "GCM", "SHA384"],
    ),
    (0xC063, &["ECDH", "ARIA256", "GCM", "SHA384"]),
    (
        0xC064,
        &["TLS", "PSK", "WITH", "ARIA", "128", "CBC", "SHA256"],
    ),
    (0xC064, &["PSK", "ARIA128", "SHA256"]),
    (
        0xC065,
        &["TLS", "PSK", "WITH", "ARIA", "256", "CBC", "SHA384"],
    ),
    (0xC065, &["PSK", "ARIA256", "SHA384"]),
    (
        0xC066,
        &["TLS", "DHE", "PSK", "WITH", "ARIA", "128", "CBC", "SHA256"],
    ),
    (0xC066, &["DHE", "PSK", "ARIA128", "SHA256"]),
    (
        0xC067,
        &["TLS", "DHE", "PSK", "WITH", "ARIA", "256", "CBC", "SHA384"],
    ),
    (0xC067, &["DHE", "PSK", "ARIA256", "SHA384"]),
    (
        0xC068,
        &["TLS", "RSA", "PSK", "WITH", "ARIA", "128", "CBC", "SHA256"],
    ),
    (0xC068, &["RSA", "PSK", "ARIA128", "SHA256"]),
    (
        0xC069,
        &["TLS", "RSA", "PSK", "WITH", "ARIA", "256", "CBC", "SHA384"],
    ),
    (0xC069, &["RSA", "PSK", "ARIA256", "SHA384"]),
    (
        0xC06A,
        &["TLS", "PSK", "WITH", "ARIA", "128", "GCM", "SHA256"],
    ),
    (0xC06A, &["PSK", "ARIA128", "GCM", "SHA256"]),
    (
        0xC06B,
        &["TLS", "PSK", "WITH", "ARIA", "256", "GCM", "SHA384"],
    ),
    (0xC06B, &["PSK", "ARIA256", "GCM", "SHA384"]),
    (
        0xC06C,
        &["TLS", "DHE", "PSK", "WITH", "ARIA", "128", "GCM", "SHA256"],
    ),
    (0xC06C, &["DHE", "PSK", "ARIA128", "GCM", "SHA256"]),
    (
        0xC06D,
        &["TLS", "DHE", "PSK", "WITH", "ARIA", "256", "GCM", "SHA384"],
    ),
    (0xC06D, &["DHE", "PSK", "ARIA256", "GCM", "SHA384"]),
    (
        0xC06E,
        &["TLS", "RSA", "PSK", "WITH", "ARIA", "128", "GCM", "SHA256"],
    ),
    (0xC06E, &["RSA", "PSK", "ARIA128", "GCM", "SHA256"]),
    (
        0xC06F,
        &["TLS", "RSA", "PSK", "WITH", "ARIA", "256", "GCM", "SHA384"],
    ),
    (0xC06F, &["RSA", "PSK", "ARIA256", "GCM", "SHA384"]),
    (
        0xC070,
        &[
            "TLS", "ECDHE", "PSK", "WITH", "ARIA", "128", "CBC", "SHA256",
        ],
    ),
    (0xC070, &["ECDHE", "PSK", "ARIA128", "SHA256"]),
    (
        0xC071,
        &[
            "TLS", "ECDHE", "PSK", "WITH", "ARIA", "256", "CBC", "SHA384",
        ],
    ),
    (0xC071, &["ECDHE", "PSK", "ARIA256", "SHA384"]),
    (
        0xC072,
        &[
            "TLS", "ECDHE", "ECDSA", "WITH", "CAMELLIA", "128", "CBC", "SHA256",
        ],
    ),
    (0xC072, &["ECDHE", "ECDSA", "CAMELLIA128", "SHA256"]),
    (
        0xC073,
        &[
            "TLS", "ECDHE", "ECDSA", "WITH", "CAMELLIA", "256", "CBC", "SHA384",
        ],
    ),
    (0xC073, &["ECDHE", "ECDSA", "CAMELLIA256", "SHA384"]),
    (
        0xC074,
        &[
            "TLS", "ECDH", "ECDSA", "WITH", "CAMELLIA", "128", "CBC", "SHA256",
        ],
    ),
    (0xC074, &["ECDH", "ECDSA", "CAMELLIA128", "SHA256"]),
    (
        0xC075,
        &[
            "TLS", "ECDH", "ECDSA", "WITH", "CAMELLIA", "256", "CBC", "SHA384",
        ],
    ),
    (0xC075, &["ECDH", "ECDSA", "CAMELLIA256", "SHA384"]),
    (
        0xC076,
        &[
            "TLS", "ECDHE", "RSA", "WITH", "CAMELLIA", "128", "CBC", "SHA256",
        ],
    ),
    (0xC076, &["ECDHE", "RSA", "CAMELLIA128", "SHA256"]),
    (
        0xC077,
        &[
            "TLS", "ECDHE", "RSA", "WITH", "CAMELLIA", "256", "CBC", "SHA384",
        ],
    ),
    (0xC077, &["ECDHE", "RSA", "CAMELLIA256", "SHA384"]),
    (
        0xC078,
        &[
            "TLS", "ECDH", "RSA", "WITH", "CAMELLIA", "128", "CBC", "SHA256",
        ],
    ),
    (0xC078, &["ECDH", "CAMELLIA128", "SHA256"]),
    (
        0xC079,
        &[
            "TLS", "ECDH", "RSA", "WITH", "CAMELLIA", "256", "CBC", "SHA384",
        ],
    ),
    (0xC079, &["ECDH", "CAMELLIA256", "SHA384"]),
    (
        0xC07A,
        &["TLS", "RSA", "WITH", "CAMELLIA", "128", "GCM", "SHA256"],
    ),
    (0xC07A, &["CAMELLIA128", "GCM", "SHA256"]),
    (
        0xC07B,
        &["TLS", "RSA", "WITH", "CAMELLIA", "256", "GCM", "SHA384"],
    ),
    (0xC07B, &["CAMELLIA256", "GCM", "SHA384"]),
    (
        0xC07C,
        &[
            "TLS", "DHE", "RSA", "WITH", "CAMELLIA", "128", "GCM", "SHA256",
        ],
    ),
    (0xC07C, &["DHE", "RSA", "CAMELLIA128", "GCM", "SHA256"]),
    (
        0xC07D,
        &[
            "TLS", "DHE", "RSA", "WITH", "CAMELLIA", "256", "GCM", "SHA384",
        ],
    ),
    (0xC07D, &["DHE", "RSA", "CAMELLIA256", "GCM", "SHA384"]),
    (
        0xC086,
        &[
            "TLS", "ECDHE", "ECDSA", "WITH", "CAMELLIA", "128", "GCM", "SHA256",
        ],
    ),
    (0xC086, &["ECDHE", "ECDSA", "CAMELLIA128", "GCM", "SHA256"]),
    (
        0xC087,
        &[
            "TLS", "ECDHE", "ECDSA", "WITH", "CAMELLIA", "256", "GCM", "SHA384",
        ],
    ),
    (0xC087, &["ECDHE", "ECDSA", "CAMELLIA256", "GCM", "SHA384"]),
    (
        0xC088,
        &[
            "TLS", "ECDH", "ECDSA", "WITH", "CAMELLIA", "128", "GCM", "SHA256",
        ],
    ),
    (0xC088, &["ECDH", "ECDSA", "CAMELLIA128", "GCM", "SHA256"]),
    (
        0xC089,
        &[
            "TLS", "ECDH", "ECDSA", "WITH", "CAMELLIA", "256", "GCM", "SHA384",
        ],
    ),
    (0xC089, &["ECDH", "ECDSA", "CAMELLIA256", "GCM", "SHA384"]),
    (
        0xC08A,
        &[
            "TLS", "ECDHE", "RSA", "WITH", "CAMELLIA", "128", "GCM", "SHA256",
        ],
    ),
    (0xC08A, &["ECDHE", "CAMELLIA128", "GCM", "SHA256"]),
    (
        0xC08B,
        &[
            "TLS", "ECDHE", "RSA", "WITH", "CAMELLIA", "256", "GCM", "SHA384",
        ],
    ),
    (0xC08B, &["ECDHE", "CAMELLIA256", "GCM", "SHA384"]),
    (
        0xC08C,
        &[
            "TLS", "ECDH", "RSA", "WITH", "CAMELLIA", "128", "GCM", "SHA256",
        ],
    ),
    (0xC08C, &["ECDH", "CAMELLIA128", "GCM", "SHA256"]),
    (
        0xC08D,
        &[
            "TLS", "ECDH", "RSA", "WITH", "CAMELLIA", "256", "GCM", "SHA384",
        ],
    ),
    (0xC08D, &["ECDH", "CAMELLIA256", "GCM", "SHA384"]),
    (
        0xC08E,
        &["TLS", "PSK", "WITH", "CAMELLIA", "128", "GCM", "SHA256"],
    ),
    (0xC08E, &["PSK", "CAMELLIA128", "GCM", "SHA256"]),
    (
        0xC08F,
        &["TLS", "PSK", "WITH", "CAMELLIA", "256", "GCM", "SHA384"],
    ),
    (0xC08F, &["PSK", "CAMELLIA256", "GCM", "SHA384"]),
    (
        0xC090,
        &[
            "TLS", "DHE", "PSK", "WITH", "CAMELLIA", "128", "GCM", "SHA256",
        ],
    ),
    (0xC090, &["DHE", "PSK", "CAMELLIA128", "GCM", "SHA256"]),
    (
        0xC091,
        &[
            "TLS", "DHE", "PSK", "WITH", "CAMELLIA", "256", "GCM", "SHA384",
        ],
    ),
    (0xC091, &["DHE", "PSK", "CAMELLIA256", "GCM", "SHA384"]),
    (
        0xC092,
        &[
            "TLS", "RSA", "PSK", "WITH", "CAMELLIA", "128", "GCM", "SHA256",
        ],
    ),
    (0xC092, &["RSA", "PSK", "CAMELLIA128", "GCM", "SHA256"]),
    (
        0xC093,
        &[
            "TLS", "RSA", "PSK", "WITH", "CAMELLIA", "256", "GCM", "SHA384",
        ],
    ),
    (0xC093, &["RSA", "PSK", "CAMELLIA256", "GCM", "SHA384"]),
    (
        0xC094,
        &["TLS", "PSK", "WITH", "CAMELLIA", "128", "CBC", "SHA256"],
    ),
    (0xC094, &["PSK", "CAMELLIA128", "SHA256"]),
    (
        0xC095,
        &["TLS", "PSK", "WITH", "CAMELLIA", "256", "CBC", "SHA384"],
    ),
    (0xC095, &["PSK", "CAMELLIA256", "SHA384"]),
    (
        0xC096,
        &[
            "TLS", "DHE", "PSK", "WITH", "CAMELLIA", "128", "CBC", "SHA256",
        ],
    ),
    (0xC096, &["DHE", "PSK", "CAMELLIA128", "SHA256"]),
    (
        0xC097,
        &[
            "TLS", "DHE", "PSK", "WITH", "CAMELLIA", "256", "CBC", "SHA384",
        ],
    ),
    (0xC097, &["DHE", "PSK", "CAMELLIA256", "SHA384"]),
    (
        0xC098,
        &[
            "TLS", "RSA", "PSK", "WITH", "CAMELLIA", "128", "CBC", "SHA256",
        ],
    ),
    (0xC098, &["RSA", "PSK", "CAMELLIA128", "SHA256"]),
    (
        0xC099,
        &[
            "TLS", "RSA", "PSK", "WITH", "CAMELLIA", "256", "CBC", "SHA384",
        ],
    ),
    (0xC099, &["RSA", "PSK", "CAMELLIA256", "SHA384"]),
    (
        0xC09A,
        &[
            "TLS", "ECDHE", "PSK", "WITH", "CAMELLIA", "128", "CBC", "SHA256",
        ],
    ),
    (0xC09A, &["ECDHE", "PSK", "CAMELLIA128", "SHA256"]),
    (
        0xC09B,
        &[
            "TLS", "ECDHE", "PSK", "WITH", "CAMELLIA", "256", "CBC", "SHA384",
        ],
    ),
    (0xC09B, &["ECDHE", "PSK", "CAMELLIA256", "SHA384"]),
    (0xC09E, &["TLS", "DHE", "RSA", "WITH", "AES", "128", "CCM"]),
    (0xC09E, &["DHE", "RSA", "AES128", "CCM"]),
    (0xC09F, &["TLS", "DHE", "RSA", "WITH", "AES", "256", "CCM"]),
    (0xC09F, &["DHE", "RSA", "AES256", "CCM"]),
    (
        0xC0A2,
        &["TLS", "DHE", "RSA", "WITH", "AES", "128", "CCM", "8"],
    ),
    (0xC0A2, &["DHE", "RSA", "AES128", "CCM8"]),
    (
        0xC0A3,
        &["TLS", "DHE", "RSA", "WITH", "AES", "256", "CCM", "8"],
    ),
    (0xC0A3, &["DHE", "RSA", "AES256", "CCM8"]),
    (0xC0A4, &["TLS", "PSK", "WITH", "AES", "128", "CCM"]),
    (0xC0A4, &["PSK", "AES128", "CCM"]),
    (0xC0A5, &["TLS", "PSK", "WITH", "AES", "256", "CCM"]),
    (0xC0A5, &["PSK", "AES256", "CCM"]),
    (0xC0A6, &["TLS", "DHE", "PSK", "WITH", "AES", "128", "CCM"]),
    (0xC0A6, &["DHE", "PSK", "AES128", "CCM"]),
    (0xC0A7, &["TLS", "DHE", "PSK", "WITH", "AES", "256", "CCM"]),
    (0xC0A7, &["DHE", "PSK", "AES256", "CCM"]),
    (0xC0A8, &["TLS", "PSK", "WITH", "AES", "128", "CCM", "8"]),
    (0xC0A8, &["PSK", "AES128", "CCM8"]),
    (0xC0A9, &["TLS", "PSK", "WITH", "AES", "256", "CCM", "8"]),
    (0xC0A9, &["PSK", "AES256", "CCM8"]),
    (
        0xC0AA,
        &["TLS", "PSK", "DHE", "WITH", "AES", "128", "CCM", "8"],
    ),
    (0xC0AA, &["DHE", "PSK", "AES128", "CCM8"]),
    (
        0xC0AB,
        &["TLS", "PSK", "DHE", "WITH", "AES", "256", "CCM", "8"],
    ),
    (0xC0AB, &["DHE", "PSK", "AES256", "CCM8"]),
    (
        0xCCAA,
        &[
            "TLS", "DHE", "RSA", "WITH", "CHACHA20", "POLY1305", "SHA256",
        ],
    ),
    (0xCCAA, &["DHE", "RSA", "CHACHA20", "POLY1305"]),
    (
        0xCCAC,
        &[
            "TLS", "ECDHE", "PSK", "WITH", "CHACHA20", "POLY1305", "SHA256",
        ],
    ),
    (0xCCAC, &["ECDHE", "PSK", "CHACHA20", "POLY1305"]),
    (
        0xCCAD,
        &[
            "TLS", "DHE", "PSK", "WITH", "CHACHA20", "POLY1305", "SHA256",
        ],
    ),
    (0xCCAD, &["DHE", "PSK", "CHACHA20", "POLY1305"]),
    (
        0xCCAE,
        &[
            "TLS", "RSA", "PSK", "WITH", "CHACHA20", "POLY1305", "SHA256",
        ],
    ),
    (0xCCAE, &["RSA", "PSK", "CHACHA20", "POLY1305"]),
];

/// The separators between the names of a list (`cs_is_separator`).
fn is_separator(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b':' | b',' | b';')
}

/// The number of the suite `name` names, by either of its names, in any
/// case; 0 for none (`Curl_cipher_suite_lookup_id`). A name starting
/// with `TLS` is split at `_`, any other at `-`, into at most eight
/// parts, as C splits them; it ends at a zero byte, as C reads it.
pub(crate) fn lookup(name: &[u8]) -> u16 {
    let name = name.split(|&b| b == 0).next().unwrap_or_default();
    if name.is_empty() {
        return 0;
    }
    let separator = if name.len() >= 3 && name[..3].eq_ignore_ascii_case(b"TLS") {
        b'_'
    } else {
        b'-'
    };
    let mut parts = [&b""[..]; 8];
    let mut n = 0;
    for part in name.split(|&b| b == separator) {
        if n == parts.len() {
            return 0;
        }
        parts[n] = part;
        n += 1;
    }
    let parts = &parts[..n];
    SUITES
        .iter()
        .find(|(_, theirs)| {
            theirs.len() == parts.len()
                && theirs
                    .iter()
                    .zip(parts)
                    .all(|(t, p)| t.as_bytes().eq_ignore_ascii_case(p))
        })
        .map_or(0, |&(id, _)| id)
}

/// The next name of the list `list` from `at` on, past the separators
/// before it: where it starts, where it ends, and the suite it names, 0
/// for none (`Curl_cipher_suite_walk_str`). The list ends at its end or
/// at a zero byte, as C reads it.
pub(crate) fn walk(list: &[u8], at: usize) -> (usize, usize, u16) {
    let end_of = |i: usize| i >= list.len() || list[i] == 0;
    let mut start = at;
    while !end_of(start) && is_separator(list[start]) {
        start += 1;
    }
    let mut end = start;
    while !end_of(end) && !is_separator(list[end]) {
        end += 1;
    }
    (start, end, lookup(&list[start..end]))
}

/// The name of suite `id`: IANA's if `rfc` and it has one, OpenSSL's if
/// not `rfc` and it has one, else the other; `TLS_UNKNOWN_0x...` for a
/// suite C does not know (`Curl_cipher_suite_get_str`).
pub(crate) fn name(id: u16, rfc: bool) -> SuiteName {
    let mut found = None;
    for (i, &(sid, parts)) in SUITES.iter().enumerate() {
        if sid != id {
            continue;
        }
        if (parts[0] != "TLS") == !rfc {
            found = Some(i);
            break;
        }
        if found.is_none() {
            found = Some(i);
        }
    }
    match found {
        Some(i) => SuiteName::Known(SUITES[i].1),
        None => SuiteName::Unknown(id),
    }
}

/// A suite's name, as C writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SuiteName {
    Known(&'static [&'static str]),
    Unknown(u16),
}

impl core::fmt::Display for SuiteName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            SuiteName::Known(parts) => {
                let separator = if parts[0] == "TLS" { "_" } else { "-" };
                for (i, part) in parts.iter().enumerate() {
                    if i > 0 {
                        f.write_str(separator)?;
                    }
                    f.write_str(part)?;
                }
                Ok(())
            }
            SuiteName::Unknown(id) => write!(f, "TLS_UNKNOWN_0x{id:04x}"),
        }
    }
}

/// The suites to offer, of those the library has, as the cipher lists
/// before TLS 1.3 (`tls12`) and for it (`tls13`) name them, one at least
/// set (`mbed_set_selected_ciphers`): TLS 1.3's first, the library's own
/// unless the list names them, then those of the list before it, the
/// library's own unless it names them; each once, the names the library
/// lacks and those named twice said. `SslCipher` if none is left.
pub(crate) fn select<G: Mbedtls>(
    lib: &G,
    io: &mut TlsCx<'_>,
    tls12: Option<&[u8]>,
    tls13: Option<&[u8]>,
) -> Result<Vec<i32>, ErrorKind> {
    let supported = lib.suites();
    let room = supported.len();
    let mut selected: Vec<i32> = Vec::new();
    selected
        .try_reserve_exact(room + 1)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    let is13 = |id: i32| lib.suite_name(id).starts_with(b"TLS1-3");
    let mut default13 = 0;
    if tls13.is_none() {
        for &id in supported.iter().filter(|&&id| is13(id)) {
            push(&mut selected, id)?;
        }
        default13 = selected.len();
    }
    for list in [tls13, tls12].into_iter().flatten() {
        let mut at = 0;
        while at < list.len() && list[at] != 0 && selected.len() < room {
            let (start, end, id) = walk(list, at);
            at = end;
            let name = &list[start..end];
            let id = i32::from(id);
            if id == 0 || !supported.contains(&id) {
                if !name.is_empty() {
                    io.info(format_args!(
                        "mbedTLS: unknown cipher in list: \"{}\"",
                        Text(name)
                    ));
                }
                continue;
            }
            if let Some(i) = selected.iter().position(|&s| s == id) {
                if i >= default13 {
                    io.info(format_args!(
                        "mbedTLS: duplicate cipher in list: \"{}\"",
                        Text(name)
                    ));
                }
                continue;
            }
            push(&mut selected, id)?;
        }
    }
    if tls12.is_none() {
        for &id in supported.iter().filter(|&&id| !is13(id)) {
            if !selected.contains(&id) {
                push(&mut selected, id)?;
            }
        }
    }
    if selected.is_empty() {
        return Err(io.fail(
            ErrorKind::SslCipher,
            format_args!("mbedTLS: no supported cipher in list"),
        ));
    }
    push(&mut selected, 0)?;
    Ok(selected)
}

/// `id` added to the selection, which has room for it.
fn push(selected: &mut Vec<i32>, id: i32) -> Result<(), ErrorKind> {
    selected
        .try_push(id)
        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curl_core::c_source::{self, Value};

    /// What unit3205's conditions are for an mbedTLS build.
    fn mbedtls(c: &str) -> bool {
        match c {
            "defined(USE_MBEDTLS)" | "defined(USE_MBEDTLS) || defined(USE_RUSTLS)" => true,
            "!(defined(USE_MBEDTLS))" => false,
            other => panic!("{other}"),
        }
    }

    /// The table is C's: each `CS_ENTRY` of `lib/vtls/cipher_suite.c`, in
    /// its order, the parts its empty arguments leave out.
    #[test]
    // Reads C's source, which Miri's isolation keeps out.
    #[cfg_attr(miri, ignore)]
    fn the_table_is_c_s() {
        let theirs = c_source::calls_where("lib/vtls/cipher_suite.c", "CS_ENTRY", mbedtls);
        // The macro's definition, which reads like a call, is no row.
        let theirs: Vec<_> = theirs
            .iter()
            .filter(|args| args[0].word() != "id")
            .collect();
        assert_eq!(theirs.len(), SUITES.len());
        for (row, (id, parts)) in theirs.iter().zip(SUITES) {
            assert_eq!(u16::try_from(row[0].int()).unwrap(), *id);
            let named: Vec<&str> = row[1..]
                .iter()
                .map(Value::word)
                .filter(|w| !w.is_empty())
                .collect();
            assert_eq!(named, *parts, "{id:#06x}");
        }
    }

    /// unit3205: each suite's IANA and OpenSSL names look up its number,
    /// its name is written as either, and a list is walked name by name,
    /// those C does not know answering 0.
    #[test]
    // Reads C's source, which Miri's isolation keeps out.
    #[cfg_attr(miri, ignore)]
    fn unit3205() {
        let rows = c_source::table("tests/unit/unit3205.c", "test_cs_list[] =", mbedtls);
        assert!(rows.len() > 100, "{}", rows.len());
        for row in &rows {
            let row = row.group();
            let id = u16::try_from(row[0].int()).unwrap();
            let (rfc, openssl) = (row[1].bytes(), row[2].bytes());
            for name in [rfc, openssl].into_iter().flatten() {
                assert_eq!(lookup(name), id, "{}", Text(name));
            }
            let expect = rfc.or(openssl).unwrap();
            assert_eq!(name(id, true).to_string().as_bytes(), expect, "{id:#06x}");
            let expect = openssl.or(rfc).unwrap();
            // No suite of the table goes by an `EDH` alias, which C's
            // test reads as `DHE`.
            assert!(!(0x0011..0x0017).contains(&id));
            assert_eq!(name(id, false).to_string().as_bytes(), expect, "{id:#06x}");
        }
        let src = c_source::source("tests/unit/unit3205.c");
        let at = src.find("cs_test_string[] =").unwrap();
        let end = at + src[at..].find(';').unwrap();
        let list: String = src[at..end].split('"').skip(1).step_by(2).collect();
        let walked = c_source::table("tests/unit/unit3205.c", "test_str_list[] =", mbedtls);
        let list = list.as_bytes();
        let mut at = 0;
        let mut i = 0;
        while at < list.len() {
            let row = walked[i].group();
            let (start, end, id) = walk(list, at);
            assert_eq!(u16::try_from(row[0].int()).unwrap(), id, "row {i}");
            assert_eq!(&list[start..end], row[1].str(), "row {i}");
            at = end;
            i += 1;
        }
        assert_eq!(i, walked.len());
    }

    /// A suite C does not know is named by its number; a name of more than
    /// eight parts, or with an empty one, names none.
    #[test]
    fn what_c_does_not_know_is_named_by_number_and_looks_up_nothing() {
        assert_eq!(name(0x1234, true).to_string(), "TLS_UNKNOWN_0x1234");
        assert_eq!(lookup(b"TLS_AES_128_GCM_SHA256_"), 0);
        assert_eq!(lookup(b"TLS_AES_128_GCM_SHA256_A_B_C_D"), 0);
        assert_eq!(lookup(b"tls_aes_128_gcm_sha256"), 0x1301);
        assert_eq!(lookup(b"TLS_AES_128_GCM_SHA256\0junk"), 0x1301);
        assert_eq!(lookup(b""), 0);
    }
}
