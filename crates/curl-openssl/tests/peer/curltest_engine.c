/*
 * A crypto engine for the peer tests, `curltest`, built by the test that
 * loads it: the certificate a file names, by `LOAD_CERT_CTRL` (as libp11's
 * pkcs11 engine gives one), and the private key a file names, by
 * `ENGINE_load_private_key`, its password asked for through the UI method
 * the caller gives, offered as the default password the caller's data
 * holds. OpenSSL finds it as `curltest.so` in `OPENSSL_ENGINES`.
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <string.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/ui.h>
#include <openssl/x509.h>

#define CMD_LOAD_CERT ENGINE_CMD_BASE

static const ENGINE_CMD_DEFN cmds[] = {
  { CMD_LOAD_CERT, "LOAD_CERT_CTRL", "Get the certificate a file names",
    ENGINE_CMD_FLAG_INTERNAL },
  { 0, NULL, NULL, 0 }
};

static int ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
  struct {
    const char *cert_id;
    X509 *cert;
  } *params = p;
  BIO *in;
  (void)e;
  (void)i;
  (void)f;
  if(cmd != CMD_LOAD_CERT || !params)
    return 0;
  in = BIO_new_file(params->cert_id, "r");
  if(!in)
    return 0;
  params->cert = PEM_read_bio_X509(in, NULL, NULL, NULL);
  BIO_free(in);
  return params->cert != NULL;
}

/* The password, from the caller's UI: the prompt is offered `data` as its
   default, which curl's reader answers with. */
static int ask(char *buf, int size, int rwflag, void *u)
{
  void **ui = u;
  UI *dialog = UI_new_method(ui[0]);
  int len = -1;
  (void)rwflag;
  if(!dialog)
    return -1;
  UI_add_user_data(dialog, ui[1]);
  if(UI_add_input_string(dialog, "curltest key password: ",
                         UI_INPUT_FLAG_DEFAULT_PWD, buf, 0, size - 1) >= 0 &&
     UI_process(dialog) == 0)
    len = (int)strlen(buf);
  UI_free(dialog);
  return len;
}

static EVP_PKEY *load_key(ENGINE *e, const char *key_id, UI_METHOD *ui_method,
                          void *callback_data)
{
  void *ui[2];
  EVP_PKEY *key;
  BIO *in = BIO_new_file(key_id, "r");
  (void)e;
  if(!in)
    return NULL;
  ui[0] = ui_method;
  ui[1] = callback_data;
  key = PEM_read_bio_PrivateKey(in, NULL, ask, ui);
  BIO_free(in);
  return key;
}

static int bind(ENGINE *e, const char *id)
{
  if(id && strcmp(id, "curltest"))
    return 0;
  return ENGINE_set_id(e, "curltest") &&
         ENGINE_set_name(e, "curl's test engine") &&
         ENGINE_set_cmd_defns(e, cmds) &&
         ENGINE_set_ctrl_function(e, ctrl) &&
         ENGINE_set_load_privkey_function(e, load_key);
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
