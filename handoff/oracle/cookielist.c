/* Prints CURLINFO_COOKIELIST after adding cookies for the given domains, in order. */
#include <stdio.h>
#include <curl/curl.h>
int main(int argc, char **argv) {
  CURL *e = curl_easy_init();
  char line[512];
  for(int i = 1; i < argc; i++) {
    snprintf(line, sizeof(line), "%s\tFALSE\t/\tFALSE\t0\tn%d\tv", argv[i], i);
    curl_easy_setopt(e, CURLOPT_COOKIELIST, line);
  }
  struct curl_slist *l = NULL;
  curl_easy_getinfo(e, CURLINFO_COOKIELIST, &l);
  for(struct curl_slist *p = l; p; p = p->next) printf("%s\n", p->data);
  curl_slist_free_all(l); curl_easy_cleanup(e); return 0;
}
