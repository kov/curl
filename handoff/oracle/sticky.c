/* Two transfers to one host on a multi; B follows a redirect after A is done.
   Prints each transfer's connection id when it completes. */
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
static size_t sink(char *p, size_t s, size_t n, void *u) { (void)p; (void)u; return s * n; }
int main(int argc, char **argv) {
  CURLM *m = curl_multi_init();
  CURL *a = curl_easy_init(), *b = curl_easy_init();
  char url[128];
  snprintf(url, sizeof(url), "http://127.0.0.1:%s/a", argv[1]);
  curl_easy_setopt(a, CURLOPT_URL, url);
  snprintf(url, sizeof(url), "http://127.0.0.1:%s/b0", argv[1]);
  curl_easy_setopt(b, CURLOPT_URL, url);
  curl_easy_setopt(b, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(a, CURLOPT_WRITEFUNCTION, sink);
  curl_easy_setopt(b, CURLOPT_WRITEFUNCTION, sink);
  curl_multi_add_handle(m, a); curl_multi_add_handle(m, b);
  int running = 1;
  while(running) {
    curl_multi_perform(m, &running);
    CURLMsg *msg; int left;
    while((msg = curl_multi_info_read(m, &left))) {
      curl_off_t id = -1;
      curl_easy_getinfo(msg->easy_handle, CURLINFO_CONN_ID, &id);
      printf("%s done: result %d conn %ld\n", msg->easy_handle == a ? "a" : "b",
             (int)msg->data.result, (long)id);
    }
    if(running) curl_multi_poll(m, NULL, 0, 100, NULL);
  }
  curl_multi_cleanup(m); return 0;
}
