/*
 * Replays add/remove churn on a C multi handle and prints the id (`mid`)
 * each added transfer gets: the oracle for the order the Rust arena hands
 * out ids. Built by gen/arena.py against the C build's libcurlu.
 *
 * Input, one per line: the table size first (16 for curl_easy_perform's
 * multi, 128 for curl_multi_init's), then "+ N" to add handle N or "- N"
 * to remove it. Output: the mid of each add, one per line.
 */
#include "curl_setup.h"
#include "urldata.h"
#include "multiif.h"

#define HANDLES 1024

int main(void)
{
  static CURL *easy[HANDLES];
  struct Curl_multi *multi;
  unsigned int size;
  char op;
  int n;

  if(scanf("%u", &size) != 1)
    return 1;
  /* As curl_easy_perform and curl_multi_init make them. */
  multi = size == 16 ? Curl_multi_handle(16, 1, 3, 7, 3) : curl_multi_init();
  if(!multi)
    return 1;
  while(scanf(" %c %d", &op, &n) == 2) {
    if(n < 0 || n >= HANDLES)
      return 1;
    if(!easy[n] && !(easy[n] = curl_easy_init()))
      return 1;
    if(op == '+') {
      if(curl_multi_add_handle(multi, easy[n]))
        return 1;
      printf("%u\n", ((struct Curl_easy *)easy[n])->mid);
    }
    else if(curl_multi_remove_handle(multi, easy[n]))
      return 1;
  }
  return 0;
}
