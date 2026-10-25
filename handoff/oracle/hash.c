/* cookie_hash_domain from lib/cookie.c, over get_top_domain's result for the argument. */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
static char up(char c) { unsigned char u = (unsigned char)c; return (char)((u >= 'a' && u <= 'z') ? u - 32 : u); }
int main(int argc, char **argv) {
  const char *d = argv[1]; size_t h = 5381;
  for(const char *p = d; *p; p++) { size_t j = (size_t)up(*p); h += h << 5; h ^= j; }
  printf("%zu\n", h % 63); return 0;
}
