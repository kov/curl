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

/* The lock calls a share keeping the cookies, the public suffix list and
   the HSTS cache makes around two transfers and the application's cookie.
   libtest2 holds the name of the HSTS file. */

static const char *t3238_kind(curl_lock_data data)
{
  switch(data) {
  case CURL_LOCK_DATA_SHARE:
    return "share";
  case CURL_LOCK_DATA_COOKIE:
    return "cookie";
  case CURL_LOCK_DATA_PSL:
    return "psl";
  case CURL_LOCK_DATA_HSTS:
    return "hsts";
  default:
    return "other";
  }
}

static void t3238_lock(CURL *curl, curl_lock_data data,
                       curl_lock_access access, void *user)
{
  (void)curl;
  (void)user;
  curl_mprintf("lock %s %s\n", t3238_kind(data),
               access == CURL_LOCK_ACCESS_SHARED ? "shared" : "single");
}

static void t3238_unlock(CURL *curl, curl_lock_data data, void *user)
{
  (void)curl;
  (void)user;
  curl_mprintf("unlock %s\n", t3238_kind(data));
}

static size_t t3238_write(char *ptr, size_t size, size_t nmemb, void *user)
{
  (void)ptr;
  (void)user;
  return size * nmemb;
}

static CURLcode test_lib3238(const char *URL)
{
  CURL *curl = NULL;
  CURLSH *share = NULL;
  struct curl_slist *headers = NULL;
  CURLcode result = CURLE_OK;
  int i;

  global_init(CURL_GLOBAL_ALL);

  share = curl_share_init();
  if(!share) {
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_PSL);
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_HSTS);
  curl_share_setopt(share, CURLSHOPT_LOCKFUNC, t3238_lock);
  curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, t3238_unlock);

  headers = curl_slist_append(NULL, "Host: www.example.com");
  if(!headers) {
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  easy_init(curl);
  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  easy_setopt(curl, CURLOPT_WRITEFUNCTION, t3238_write);
  easy_setopt(curl, CURLOPT_HSTS, libtest_arg2);
  easy_setopt(curl, CURLOPT_SHARE, share);
  easy_setopt(curl, CURLOPT_COOKIEFILE, "");

  for(i = 0; i < 2; i++) {
    curl_mprintf("perform\n");
    result = curl_easy_perform(curl);
    if(result)
      goto test_cleanup;
  }
  curl_mprintf("application's cookie\n");
  easy_setopt(curl, CURLOPT_COOKIELIST,
              "Set-Cookie: q=1; domain=www.example.com");
  curl_mprintf("cleanup\n");

test_cleanup:
  curl_easy_cleanup(curl);
  curl_share_cleanup(share);
  curl_slist_free_all(headers);
  curl_global_cleanup();
  return result;
}
