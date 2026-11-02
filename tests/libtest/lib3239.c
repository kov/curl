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

/* Whether a handle whose jar has gone, by leaving a share keeping cookies or
   by CURLOPT_COOKIEFILE NULL, has one at its next transfer because
   CURLOPT_COOKIEJAR is set. libtest2 holds the prefix of the jars' names. */

static size_t t3239_write(char *ptr, size_t size, size_t nmemb, void *user)
{
  (void)ptr;
  (void)user;
  return size * nmemb;
}

static CURLcode t3239_case(const char *URL, CURLSH *share, int which,
                           const char *what)
{
  CURL *curl = NULL;
  struct curl_slist *list = NULL;
  struct curl_slist *at;
  CURLcode result = CURLE_OK;
  int count = 0;
  FILE *written;
  char jar[256];

  curl_msnprintf(jar, sizeof(jar), "%s%d", libtest_arg2, which);

  easy_init(curl);
  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_WRITEFUNCTION, t3239_write);
  easy_setopt(curl, CURLOPT_COOKIEJAR, jar);
  if(which == 1 || which == 3 || which == 4) {
    easy_setopt(curl, CURLOPT_SHARE, share);
    easy_setopt(curl, CURLOPT_SHARE, NULL);
  }
  if(which == 2)
    easy_setopt(curl, CURLOPT_COOKIEFILE, NULL);
  if(which == 3)
    easy_setopt(curl, CURLOPT_COOKIEJAR, jar);
  if(which == 4)
    easy_setopt(curl, CURLOPT_COOKIEFILE, "");

  result = curl_easy_perform(curl);
  if(result)
    goto test_cleanup;
  result = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &list);
  if(result)
    goto test_cleanup;
  for(at = list; at; at = at->next)
    count++;
  curl_slist_free_all(list);

  curl_easy_cleanup(curl);
  curl = NULL;
  written = curlx_fopen(jar, "rb");
  curl_mprintf("%s: %d cookies, %s\n", what, count,
               written ? "written" : "not written");
  if(written)
    curlx_fclose(written);

test_cleanup:
  curl_easy_cleanup(curl);
  return result;
}

static CURLcode test_lib3239(const char *URL)
{
  static const char * const cases[] = {
    "named", "left a share", "forgotten", "named again", "a file after"
  };
  CURLSH *share = NULL;
  CURLcode result = CURLE_OK;
  int i;

  global_init(CURL_GLOBAL_ALL);

  share = curl_share_init();
  if(!share) {
    curl_global_cleanup();
    return TEST_ERR_FAILURE;
  }
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);

  for(i = 0; i < 5 && !result; i++)
    result = t3239_case(URL, share, i, cases[i]);

  curl_share_cleanup(share);
  curl_global_cleanup();
  return result;
}
