/* The values and layouts of libssh's headers that src/sys.rs declares,
 * as the headers have them, in the order the crate's tests compare them
 * with sys.rs's. */

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>

#define ATTR(f) (int64_t)offsetof(struct sftp_attributes_struct, f)
#define KH(f) (int64_t)offsetof(struct ssh_knownhosts_entry, f)

const int64_t curl_libssh_values[] = {
  SSH_OK, SSH_ERROR, SSH_AGAIN,
  SSH_AUTH_SUCCESS, SSH_AUTH_DENIED, SSH_AUTH_PARTIAL, SSH_AUTH_INFO,
  SSH_AUTH_AGAIN, SSH_AUTH_ERROR,
  SSH_OPTIONS_HOST, SSH_OPTIONS_PORT, SSH_OPTIONS_FD, SSH_OPTIONS_USER,
  SSH_OPTIONS_KNOWNHOSTS, SSH_OPTIONS_COMPRESSION,
  SSH_OPTIONS_GLOBAL_KNOWNHOSTS,
  SSH_READ_PENDING, SSH_WRITE_PENDING,
  SSH_KNOWN_HOSTS_ERROR, SSH_KNOWN_HOSTS_NOT_FOUND, SSH_KNOWN_HOSTS_UNKNOWN,
  SSH_KNOWN_HOSTS_OK, SSH_KNOWN_HOSTS_CHANGED, SSH_KNOWN_HOSTS_OTHER,
  SSH_KEYTYPE_DSS, SSH_KEYTYPE_RSA, SSH_KEYTYPE_RSA1, SSH_KEYTYPE_ECDSA,
  SSH_KEYTYPE_ED25519, SSH_KEYTYPE_ECDSA_P256, SSH_KEYTYPE_ECDSA_P384,
  SSH_KEYTYPE_ECDSA_P521,
  SSH_PUBLICKEY_HASH_MD5, SSH_PUBLICKEY_HASH_SHA256,
  SSH_SCP_WRITE, SSH_SCP_READ, SSH_SCP_REQUEST_NEWFILE,
  O_RDONLY, O_WRONLY, O_CREAT, O_TRUNC, O_APPEND,
  SSH_FILEXFER_ATTR_UIDGID, SSH_FILEXFER_ATTR_PERMISSIONS,
  SSH_FILEXFER_ATTR_ACMODTIME,
  (int64_t)sizeof(struct sftp_attributes_struct),
  ATTR(name), ATTR(longname), ATTR(flags), ATTR(type), ATTR(size), ATTR(uid),
  ATTR(gid), ATTR(owner), ATTR(group), ATTR(permissions), ATTR(atime64),
  ATTR(atime), ATTR(atime_nseconds), ATTR(createtime),
  ATTR(createtime_nseconds), ATTR(mtime64), ATTR(mtime),
  ATTR(mtime_nseconds), ATTR(acl), ATTR(extended_count),
  ATTR(extended_type), ATTR(extended_data),
  (int64_t)sizeof(struct ssh_knownhosts_entry),
  KH(hostname), KH(unparsed), KH(publickey), KH(comment),
  (int64_t)sizeof(mode_t), SSH_FILEXFER_ATTR_SIZE,
};

_Static_assert(sizeof(curl_libssh_values) / sizeof(curl_libssh_values[0])
               == 75, "src/sys.rs's LAYOUT_LEN");
