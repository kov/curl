/* mbedTLS's values and layouts as its headers have them, for this build of
 * the library (its mbedtls_config.h decides them).
 *
 * curl_mbedtls_values: the constants src/sys.rs declares, in the order
 * the crate's tests compare them with sys.rs's.
 *
 * curl_mbedtls_layout: what the binding reads as it runs: the size and
 * alignment of each object it makes for the library to fill in (the
 * library's objects are the caller's to allocate), and the offsets of
 * the fields it reads or writes itself, which the headers reach only
 * through inline functions or fields (src/sys.rs's `Layout`). */

#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <stddef.h>
#include <stdint.h>
#include <mbedtls/version.h>
#include <mbedtls/build_info.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <psa/crypto.h>

#if MBEDTLS_VERSION_NUMBER < 0x03020000 || MBEDTLS_VERSION_NUMBER >= 0x04000000
#error "mbedTLS 3.2.0 or later, before 4.0.0, is required"
#endif

/* What `lib/vtls/mbedtls.c` needs of the library's configuration for the
 * build it is measured as: the RNG shared by every session is called from
 * any thread, which needs its lock. */
#ifndef MBEDTLS_THREADING_C
#error "mbedTLS built without MBEDTLS_THREADING_C"
#endif
#ifndef MBEDTLS_CTR_DRBG_C
#error "MBEDTLS_CTR_DRBG_C is required for mbedTLS 3.x"
#endif
#if !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_PEM_PARSE_C) ||          \
  !defined(MBEDTLS_X509_CRL_PARSE_C) || !defined(MBEDTLS_SSL_ALPN) ||       \
  !defined(MBEDTLS_PK_WRITE_C) || !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
#error "mbedTLS built without files, PEM, CRLs, ALPN or the peer's certificate"
#endif
#if !defined(MBEDTLS_SSL_PROTO_TLS1_2) || !defined(MBEDTLS_SSL_PROTO_TLS1_3) || \
  !defined(MBEDTLS_SSL_SESSION_TICKETS) || !defined(MBEDTLS_SSL_RENEGOTIATION) || \
  !defined(MBEDTLS_VERSION_C) || !defined(MBEDTLS_ERROR_C) ||                  \
  defined(MBEDTLS_X509_REMOVE_INFO) ||                                         \
  defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#error "mbedTLS built otherwise than the configuration this binding follows"
#endif

_Static_assert(sizeof(mbedtls_ssl_protocol_version) == sizeof(int),
               "the protocol version is an int");

const int64_t curl_mbedtls_values[] = {
  MBEDTLS_ERR_SSL_WANT_READ, MBEDTLS_ERR_SSL_WANT_WRITE,
  MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET,
  MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY, MBEDTLS_ERR_SSL_ALLOC_FAILED,
  MBEDTLS_ERR_X509_CERT_VERIFY_FAILED, MBEDTLS_ERR_PK_TYPE_MISMATCH,
  MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
  MBEDTLS_SSL_PRESET_DEFAULT, MBEDTLS_SSL_VERIFY_REQUIRED,
  MBEDTLS_SSL_RENEGOTIATION_ENABLED, MBEDTLS_SSL_SESSION_TICKETS_DISABLED,
  MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_ENABLED,
  MBEDTLS_SSL_VERSION_TLS1_2, MBEDTLS_SSL_VERSION_TLS1_3,
  MBEDTLS_X509_BADCERT_CN_MISMATCH, MBEDTLS_PK_RSA, MBEDTLS_PK_ECKEY,
  MBEDTLS_CTR_DRBG_PR_ON, PSA_SUCCESS,
  /* PUB_DER_MAX_BYTES's parts. */
  MBEDTLS_MPI_MAX_SIZE, MBEDTLS_ECP_MAX_BYTES,
};

#define SIZE(t) (int64_t)sizeof(t), (int64_t)_Alignof(t)

const int64_t curl_mbedtls_layout[] = {
  SIZE(mbedtls_ssl_context), SIZE(mbedtls_ssl_config),
  SIZE(mbedtls_x509_crt), SIZE(mbedtls_x509_crl), SIZE(mbedtls_pk_context),
  SIZE(mbedtls_ssl_session), SIZE(mbedtls_entropy_context),
  SIZE(mbedtls_ctr_drbg_context),
  (int64_t)offsetof(mbedtls_x509_crt, raw.len),
  (int64_t)offsetof(mbedtls_x509_crt, raw.p),
  (int64_t)offsetof(mbedtls_x509_crt, next),
  (int64_t)offsetof(mbedtls_x509_crt, pk),
  (int64_t)offsetof(mbedtls_ssl_config, min_tls_version),
  (int64_t)offsetof(mbedtls_ssl_config, max_tls_version),
  (int64_t)offsetof(mbedtls_ssl_context, tls_version),
};

_Static_assert(sizeof(curl_mbedtls_values) / sizeof(curl_mbedtls_values[0])
               == 23, "src/sys.rs's VALUES_LEN");
_Static_assert(sizeof(curl_mbedtls_layout) / sizeof(curl_mbedtls_layout[0])
               == 23, "src/sys.rs's LAYOUT_LEN");
