/* The values of the GSS-API header that src/sys.rs declares, as the
 * header C includes has them (lib/urldata.h: <gss.h> for GNU GSS,
 * <gssapi/gssapi.h> otherwise), in the order the crate's tests compare
 * them with sys.rs's. A macro the header lacks is -1. */

#include <stddef.h>
#include <stdint.h>
#ifdef CURL_GSS_GNU
#include <gss.h>
#else
#include <gssapi/gssapi.h>
#endif

const int64_t curl_gssapi_values[] = {
  GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED, GSS_S_FAILURE, GSS_S_NO_CONTEXT,
  GSS_ERROR(GSS_S_FAILURE) != 0, GSS_ERROR(GSS_S_CONTINUE_NEEDED) != 0,
  GSS_ERROR(0x0000ffff) != 0, GSS_ERROR(0x01000000) != 0,
  GSS_C_DELEG_FLAG, GSS_C_MUTUAL_FLAG, GSS_C_REPLAY_FLAG, GSS_C_CONF_FLAG,
  GSS_C_INTEG_FLAG,
#ifdef GSS_C_DELEG_POLICY_FLAG
  GSS_C_DELEG_POLICY_FLAG,
#else
  -1,
#endif
  GSS_C_INITIATE, (int64_t)GSS_C_INDEFINITE, GSS_C_GSS_CODE,
  GSS_C_MECH_CODE, GSS_C_QOP_DEFAULT,
  (int64_t)sizeof(OM_uint32),
  (int64_t)sizeof(gss_OID_desc), (int64_t)offsetof(gss_OID_desc, elements),
  (int64_t)sizeof(gss_OID_set_desc),
  (int64_t)offsetof(gss_OID_set_desc, elements),
  (int64_t)sizeof(gss_buffer_desc), (int64_t)offsetof(gss_buffer_desc, value),
  (int64_t)sizeof(struct gss_channel_bindings_struct),
  (int64_t)offsetof(struct gss_channel_bindings_struct, initiator_address),
  (int64_t)offsetof(struct gss_channel_bindings_struct, acceptor_addrtype),
  (int64_t)offsetof(struct gss_channel_bindings_struct, acceptor_address),
  (int64_t)offsetof(struct gss_channel_bindings_struct, application_data),
};

_Static_assert(sizeof(curl_gssapi_values) / sizeof(curl_gssapi_values[0])
               == 31, "src/sys.rs's LAYOUT_LEN");

#ifdef CURL_GSS_GNU
/* What C's curl -V names after "libgss/" (lib/version.c). */
const char curl_gssapi_gnu_version[] = GSS_VERSION;
#endif
