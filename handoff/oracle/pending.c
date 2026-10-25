/* Host limit 1: A runs, B waits; A is removed; then one curl_multi_wait.
   Prints B's text trace lines from the removal on. */
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
static int phase = 0;
static int dbg(CURL *h, curl_infotype t, char *d, size_t n, void *u) {
  if(t == CURLINFO_TEXT && u) printf("%s: %.*s", (char *)u, (int)n, d);
  return 0;
}
static size_t sink(char *p, size_t s, size_t n, void *u) { (void)p; (void)u; return s * n; }
int main(int argc, char **argv) {
  curl_global_trace("multi");
  CURLM *m = curl_multi_init();
  curl_multi_setopt(m, CURLMOPT_MAX_HOST_CONNECTIONS, 1L);
  CURL *a = curl_easy_init(), *b = curl_easy_init();
  char url[128];
  snprintf(url, sizeof(url), "http://127.0.0.1:%s/b0", argv[1]);
  curl_easy_setopt(a, CURLOPT_URL, url);
  snprintf(url, sizeof(url), "http://127.0.0.1:%s/a", argv[1]);
  curl_easy_setopt(b, CURLOPT_URL, url);
  CURL *both[2] = {a, b};
  const char *names[2] = {"A", "B"};
  for(int i = 0; i < 2; i++) {
    curl_easy_setopt(both[i], CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(both[i], CURLOPT_DEBUGFUNCTION, dbg);
    curl_easy_setopt(both[i], CURLOPT_DEBUGDATA, (void *)names[i]);
    curl_easy_setopt(both[i], CURLOPT_WRITEFUNCTION, sink);
  }
  curl_multi_add_handle(m, a); curl_multi_add_handle(m, b);
  int running = 2;
  /* A is sent and waits for its slow answer; B waits for room. */
  for(int i = 0; i < 3; i++) {
    curl_multi_perform(m, &running);
    curl_multi_poll(m, NULL, 0, 50, NULL);
  }
  phase = 1;
  printf("-- remove A\n");
  curl_multi_remove_handle(m, a);
  printf("-- wait\n");
  int n = 0;
  curl_multi_wait(m, NULL, 0, 0, &n);
  printf("-- end\n");
  phase = 0;
  curl_multi_remove_handle(m, b);
  curl_easy_cleanup(a); curl_easy_cleanup(b); curl_multi_cleanup(m); return 0;
}
