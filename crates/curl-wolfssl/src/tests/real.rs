//! The real library, as far as it goes without a peer: what the binding
//! makes it makes and frees.

use curl_alloc::TryArc;

use crate::library::{Ctx as _, Ssl as _, Store as _, Wolfssl as _};
use crate::sys;
use crate::wolfssl::{self, Method, WOLFSSL};

#[test]
// Calls into C, which Miri cannot run.
#[cfg_attr(miri, ignore)]
fn the_library_makes_and_frees_what_the_binding_asks() {
    assert!(wolfssl::init());
    assert!(crate::version().to_string().starts_with("wolfSSL/5."));
    let method = TryArc::try_new(Method::new().expect("a method")).unwrap();
    let mut ctx = WOLFSSL.ctx(&method).expect("a context");
    assert!(ctx.min_version(0x0303));
    assert!(ctx.max_version(0x0304));
    assert!(!ctx.min_version(0x0399));
    assert!(ctx.cipher_list(Some(c"TLS13-AES128-GCM-SHA256")));
    assert!(!ctx.cipher_list(Some(c"NO-SUCH-CIPHER")));
    assert!(ctx.groups(c"X25519:P-256"));
    assert!(ctx.sni(b"example.com"));
    // A store of its own, counted and given to the context.
    let store = WOLFSSL.new_store().expect("a store");
    let again = store.another().expect("counted");
    ctx.set_store(store);
    assert!(ctx.uses_store(&again));
    assert!(ctx.store().is_some());
    assert!(!ctx.ca_locations(Some(c"/no/such/file.pem"), None));
    let mut ssl = ctx.ssl().expect("a session object");
    assert!(ssl.alpn(b"h2,http/1.1"));
    assert!(ssl.check_domain(c"example.com"));
    ssl.bio().expect("a BIO");
    assert_eq!(ssl.peer_cert(), crate::library::PeerCert::None);
    assert!(!ssl.pending());
    assert_eq!(
        ssl.resume(b"not a session"),
        crate::library::Resume::Undecoded
    );
    // The context may go before its session object, which holds it.
    drop(ctx);
    drop(ssl);
    drop(again);
    // The suites, TLS 1.3's named as the library names them.
    let names: Vec<_> = (0..)
        .map_while(|i| WOLFSSL.cipher(i))
        .map(|n| String::from_utf8_lossy(n).into_owned())
        .collect();
    assert!(names.iter().any(|n| n.starts_with("TLS13-")), "{names:?}");
    // Its words for one of its numbers.
    let words = WOLFSSL
        .strerror(sys::ASN_NO_SIGNER_E.cast_unsigned())
        .to_string();
    assert!(!words.is_empty());
    drop(method);
    wolfssl::cleanup();
}

#[test]
// Calls into C, which Miri cannot run.
#[cfg_attr(miri, ignore)]
fn the_library_names_itself() {
    let v = wolfssl::version();
    let text = std::str::from_utf8(v).unwrap();
    assert!(text.starts_with("5."), "{text}");
}
