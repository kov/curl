/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "first.h"

/* The SSH key function: what it is given, then each of its answers in
   turn, over a known-hosts file that starts empty. */

struct t3612_said {
  int answer;
};

static int t3612_keyfunc(CURL *curl, const struct curl_khkey *known,
                         const struct curl_khkey *found,
                         enum curl_khmatch match, void *userp)
{
  struct t3612_said *said = (struct t3612_said *)userp;
  (void)curl;
  curl_mprintf("match %d, known %s", (int)match, known ? "given" : "none");
  if(known)
    curl_mprintf(" (type %d, length %s)", (int)known->keytype,
                 known->len == strlen(known->key) ? "its text's" : "wrong");
  curl_mprintf(", found type %d, length %s, answer %d\n",
               (int)found->keytype,
               found->len && found->len == strlen(found->key) ?
               "its text's" : "wrong", said->answer);
  return said->answer;
}

/* One transfer, the key function answering `answer`. */
static CURLcode t3612_once(const char *URL, int answer)
{
  struct t3612_said said;
  CURLcode result = CURLE_OK;
  CURLcode performed;
  CURL *curl = NULL;

  said.answer = answer;
  easy_init(curl);
  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_NOBODY, 1L);
  easy_setopt(curl, CURLOPT_SSH_KNOWNHOSTS, libtest_arg2);
  easy_setopt(curl, CURLOPT_USERPWD, libtest_arg3);
  easy_setopt(curl, CURLOPT_SSH_PUBLIC_KEYFILE, libtest_arg4);
  easy_setopt(curl, CURLOPT_SSH_PRIVATE_KEYFILE, libtest_arg5);
  easy_setopt(curl, CURLOPT_SSH_KEYFUNCTION, t3612_keyfunc);
  easy_setopt(curl, CURLOPT_SSH_KEYDATA, &said);
  performed = curl_easy_perform(curl);
  curl_mprintf("result %d\n", (int)performed);

test_cleanup:
  curl_easy_cleanup(curl);
  return result;
}

static CURLcode test_lib3612(const char *URL)
{
  CURLcode result = CURLE_OK;

  if(!libtest_arg5) {
    curl_mfprintf(stderr, "Usage: <url> <known hosts> <user:pwd> "
                  "<public key> <private key>\n");
    return TEST_ERR_USAGE;
  }

  global_init(CURL_GLOBAL_ALL);

  result = t3612_once(URL, CURLKHSTAT_FINE_ADD_TO_FILE);
  if(!result)
    result = t3612_once(URL, CURLKHSTAT_FINE);
  if(!result)
    result = t3612_once(URL, CURLKHSTAT_REJECT);

  curl_global_cleanup();
  return result;
}
