/* The values of GnuTLS's and nettle's headers that src/sys.rs declares,
 * as the headers have them, in the order the crate's tests compare them
 * with sys.rs's. */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/ocsp.h>
#include <nettle/eddsa.h>

const int64_t curl_gnutls_values[] = {
  GNUTLS_E_SUCCESS, GNUTLS_E_FATAL_ALERT_RECEIVED,
  GNUTLS_E_WARNING_ALERT_RECEIVED, GNUTLS_E_AGAIN, GNUTLS_E_REHANDSHAKE,
  GNUTLS_E_NO_CERTIFICATE_FOUND, GNUTLS_E_SHORT_MEMORY_BUFFER,
  GNUTLS_E_INTERRUPTED, GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE,
  GNUTLS_CLIENT, GNUTLS_FORCE_CLIENT_CERT, GNUTLS_ENABLE_EARLY_DATA,
  GNUTLS_NO_END_OF_EARLY_DATA,
  GNUTLS_CRD_CERTIFICATE, GNUTLS_NAME_DNS, GNUTLS_SHUT_RDWR,
  GNUTLS_X509_FMT_DER, GNUTLS_X509_FMT_PEM, GNUTLS_ALPN_MANDATORY,
  (int64_t)GNUTLS_HANDSHAKE_ANY, GNUTLS_HANDSHAKE_NEW_SESSION_TICKET,
  GNUTLS_HOOK_POST, GNUTLS_SFLAGS_EARLY_DATA,
  GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT,
  GNUTLS_CERT_INVALID, GNUTLS_CERT_SIGNER_NOT_FOUND,
  GNUTLS_CERT_INSECURE_ALGORITHM, GNUTLS_CERT_NOT_ACTIVATED,
  GNUTLS_CERT_EXPIRED, GNUTLS_CERT_INVALID_OCSP_STATUS,
  GNUTLS_SSL3, GNUTLS_TLS1_0, GNUTLS_TLS1_1, GNUTLS_TLS1_2, GNUTLS_TLS1_3,
  GNUTLS_PKCS_USE_PKCS12_3DES, GNUTLS_PKCS_USE_PKCS12_ARCFOUR,
  GNUTLS_PKCS_USE_PKCS12_RC2_40, GNUTLS_PKCS_USE_PBES2_3DES,
  GNUTLS_PKCS_USE_PBES2_AES_128, GNUTLS_PKCS_USE_PBES2_AES_192,
  GNUTLS_PKCS_USE_PBES2_AES_256,
  GNUTLS_OCSP_RESP_SUCCESSFUL, GNUTLS_OCSP_CERT_GOOD,
  GNUTLS_OCSP_CERT_REVOKED,
  ED25519_KEY_SIZE, ED25519_SIGNATURE_SIZE,
  (int64_t)sizeof(gnutls_datum_t), (int64_t)offsetof(gnutls_datum_t, data),
  (int64_t)offsetof(gnutls_datum_t, size),
  (int64_t)sizeof(time_t), (int64_t)sizeof(ssize_t),
};

const char *const curl_gnutls_oid_cn = GNUTLS_OID_X520_COMMON_NAME;

_Static_assert(sizeof(curl_gnutls_values) / sizeof(curl_gnutls_values[0])
               == 52, "src/sys.rs's LAYOUT_LEN");
