/* wolfSSL's values as its headers have them, for this build of the library
 * (its options.h decides them), and the configuration the binding follows.
 *
 * curl_wolfssl_values: the constants src/sys.rs declares, in the order
 * the crate's tests compare them with sys.rs's. */

#include <stdint.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/version.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/openssl/bio.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/ed25519.h>

#if LIBWOLFSSL_VERSION_HEX < 0x05000000
#error "wolfSSL 5.0.0 or greater required"
#endif

/* What `lib/vtls/wolfssl.c` does in the build it is measured as (the CI's
 * `--enable-all`): the BIO chain over the connection, its session export,
 * ALPN, SNI, TLS 1.3 and its early data, the peer's certificate kept, the
 * OpenSSL layer (the TLS 1.2 key log, the curve list as groups), the
 * system's CA store, and wolfCrypt's Ed25519 for HTTP message signatures.
 * Not the TLS 1.3 secret callback nor secure renegotiation, which the
 * build has neither of. */
#if !defined(OPENSSL_EXTRA) || !defined(HAVE_EX_DATA) || !defined(HAVE_ALPN) || \
  !defined(HAVE_SNI) || !defined(WOLFSSL_TLS13) || !defined(WOLFSSL_EARLY_DATA) || \
  !defined(KEEP_PEER_CERT) || !defined(WOLFSSL_SYS_CA_CERTS) ||                  \
  !defined(WOLFSSL_BIO_CTRL_EOF) || !defined(HAVE_ED25519) ||                 \
  !defined(HAVE_ED25519_KEY_IMPORT) || !defined(HAVE_ED25519_SIGN)
#error "wolfSSL built without what the binding follows (--enable-all)"
#endif
#if defined(HAVE_SECRET_CALLBACK) || defined(HAVE_SECURE_RENEGOTIATION) || \
  defined(NO_FILESYSTEM) || defined(OPENSSL_COEXIST) || defined(WC_NO_CONSTRUCTORS)
#error "wolfSSL built otherwise than the configuration this binding follows"
#endif

const int64_t curl_wolfssl_values[] = {
  WOLFSSL_SUCCESS, WOLFSSL_ERROR_NONE, WOLFSSL_ERROR_WANT_READ,
  WOLFSSL_ERROR_WANT_WRITE, WOLFSSL_ERROR_ZERO_RETURN, WOLFSSL_ALPN_NOT_FOUND,
  DOMAIN_NAME_MISMATCH, ASN_NO_SIGNER_E, ASN_AFTER_DATE_E, ASN_BEFORE_DATE_E,
  WOLFSSL_FILETYPE_PEM, WOLFSSL_FILETYPE_ASN1, WOLFSSL_VERIFY_NONE,
  WOLFSSL_VERIFY_PEER, WOLFSSL_SNI_HOST_NAME,
  WOLFSSL_ALPN_CONTINUE_ON_MISMATCH, WOLFSSL_LOAD_FLAG_IGNORE_ERR,
  WOLFSSL_SENT_SHUTDOWN, WOLFSSL_EARLY_DATA_REJECTED, WOLFSSL_BIO_MEMORY,
  WOLFSSL_BIO_FLAG_READ, WOLFSSL_BIO_FLAG_WRITE, WOLFSSL_BIO_FLAG_RETRY,
  WOLFSSL_BIO_CTRL_EOF, WOLFSSL_BIO_CTRL_GET_CLOSE, WOLFSSL_BIO_CTRL_SET_CLOSE,
  WOLFSSL_BIO_CTRL_FLUSH, WOLFSSL_BIO_CTRL_DUP, WOLFSSL_SSLV3,
  WOLFSSL_TLSV1_2, INVALID_DEVID, ED25519_KEY_SIZE, ED25519_SIG_SIZE,
};

_Static_assert(sizeof(curl_wolfssl_values) / sizeof(curl_wolfssl_values[0])
               == 33, "src/sys.rs's VALUES");
_Static_assert(ED25519_PUB_KEY_SIZE == 32, "src/sys.rs's ED25519_PUB_KEY_SIZE");
