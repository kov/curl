/* Host limit 1: A runs (slow answer), B and C wait; A is removed; then one
   curl_multi_wait. Prints B's and C's MULTI lines from the removal on. */
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
static int phase = 0;
static int dbg(CURL *h, curl_infotype t, char *d, size_t n, void *u) {
  (void)h;
  if(t == CURLINFO_TEXT && phase && strcmp((char *)u, "A")) printf("%s: %.*s", (char *)u, (int)n, d);
  return 0;
}
static size_t sink(char *p, size_t s, size_t n, void *u) { (void)p; (void)u; return s * n; }
int main(int argc, char **argv) {
  curl_global_trace("multi");
  CURLM *m = curl_multi_init();
  curl_multi_setopt(m, CURLMOPT_MAX_HOST_CONNECTIONS, 1L);
  CURL *h[3]; const char *names[3] = {"A", "B", "C"};
  char url[128];
  for(int i = 0; i < 3; i++) {
    h[i] = curl_easy_init();
    snprintf(url, sizeof(url), "http://127.0.0.1:%s/%s", argv[1], i ? "a" : "b0");
    curl_easy_setopt(h[i], CURLOPT_URL, url);
    curl_easy_setopt(h[i], CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(h[i], CURLOPT_DEBUGFUNCTION, dbg);
    curl_easy_setopt(h[i], CURLOPT_DEBUGDATA, (void *)names[i]);
    curl_easy_setopt(h[i], CURLOPT_WRITEFUNCTION, sink);
    curl_multi_add_handle(m, h[i]);
  }
  int running;
  for(int i = 0; i < 3; i++) { curl_multi_perform(m, &running); curl_multi_poll(m, NULL, 0, 50, NULL); }
  phase = 1;
  printf("-- remove A\n");
  curl_multi_remove_handle(m, h[0]);
  printf("-- wait\n");
  int n = 0;
  curl_multi_wait(m, NULL, 0, 0, &n);
  printf("-- end\n");
  phase = 0;
  for(int i = 1; i < 3; i++) curl_multi_remove_handle(m, h[i]);
  curl_multi_cleanup(m); return 0;
}
