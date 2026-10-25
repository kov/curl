#include <stdio.h>
#include <curl/curl.h>
int main(void) {
  long vals[] = {0, -1, 1, 5, 4294967295L, 4294967296L};
  CURLM *m = curl_multi_init();
  for(int i = 0; i < 6; i++)
    printf("threads_max %ld -> %d\n", vals[i], (int)curl_multi_setopt(m, CURLMOPT_RESOLVE_THREADS_MAX, vals[i]));
  printf("quick_exit 1 -> %d\n", (int)curl_multi_setopt(m, CURLMOPT_QUICK_EXIT, 1L));
  printf("quick_exit 0 -> %d\n", (int)curl_multi_setopt(m, CURLMOPT_QUICK_EXIT, 0L));
  CURL *e = curl_easy_init();
  printf("easy quick_exit -> %d\n", (int)curl_easy_setopt(e, CURLOPT_QUICK_EXIT, 1L));
  curl_easy_cleanup(e);
  curl_multi_cleanup(m);
  return 0;
}
