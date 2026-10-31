/* The values and layouts of libldap's and liblber's headers that
 * src/sys.rs declares, as the headers have them, in the order the
 * crate's tests compare them with sys.rs's. */

#include <stddef.h>
#include <stdint.h>
#include <ldap.h>

#define URL(f) (int64_t)offsetof(LDAPURLDesc, f)
#define API(f) (int64_t)offsetof(LDAPAPIInfo, f)
#define SBIOD(f) (int64_t)offsetof(Sockbuf_IO_Desc, f)
#define SBIO(f) (int64_t)offsetof(Sockbuf_IO, f)

const int64_t curl_ldap_values[] = {
  LDAP_SUCCESS, LDAP_OPT_SUCCESS, LDAP_OPT_API_INFO, LDAP_OPT_REFERRALS,
  LDAP_OPT_PROTOCOL_VERSION, LDAP_OPT_SOCKBUF, LDAP_API_INFO_VERSION,
  LDAP_MSG_ONE, LDAP_RES_BIND, LDAP_RES_SEARCH_ENTRY,
  LDAP_RES_SEARCH_REFERENCE, LDAP_RES_SEARCH_RESULT, LDAP_RES_EXTENDED,
  LBER_SB_OPT_DATA_READY, LBER_SB_OPT_SET_MAX_INCOMING,
  LBER_SBIOD_LEVEL_TRANSPORT, LDAP_URL_SUCCESS, LDAP_URL_ERR_MEM,
  (int64_t)sizeof(struct berval), (int64_t)offsetof(struct berval, bv_len),
  (int64_t)offsetof(struct berval, bv_val), (int64_t)sizeof(ber_len_t),
  (int64_t)sizeof(ber_slen_t), (int64_t)sizeof(ber_socket_t),
  (int64_t)sizeof(LDAPURLDesc), URL(lud_next), URL(lud_scheme),
  URL(lud_host), URL(lud_port), URL(lud_dn), URL(lud_attrs), URL(lud_scope),
  URL(lud_filter), URL(lud_exts), URL(lud_crit_exts),
  (int64_t)sizeof(LDAPAPIInfo), API(ldapai_info_version),
  API(ldapai_api_version), API(ldapai_protocol_version),
  API(ldapai_extensions), API(ldapai_vendor_name),
  API(ldapai_vendor_version),
  (int64_t)sizeof(Sockbuf_IO_Desc), SBIOD(sbiod_level), SBIOD(sbiod_sb),
  SBIOD(sbiod_io), SBIOD(sbiod_pvt), SBIOD(sbiod_next),
  (int64_t)sizeof(Sockbuf_IO), SBIO(sbi_setup), SBIO(sbi_remove),
  SBIO(sbi_ctrl), SBIO(sbi_read), SBIO(sbi_write), SBIO(sbi_close),
};

_Static_assert(sizeof(curl_ldap_values) / sizeof(curl_ldap_values[0])
               == 55, "src/sys.rs's LAYOUT_LEN");
