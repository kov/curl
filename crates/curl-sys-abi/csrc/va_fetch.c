/*
 * Read printf arguments from a va_list, for the types stable Rust cannot
 * read itself: `long double` (128 bits on aarch64, 80 on x86_64). Used
 * only for formats with a %L conversion when the shim is built without
 * its `nightly` feature; src/printf/mod.rs holds the matching type tags.
 */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum {
  VA_INT,
  VA_UINT,
  VA_LONG,
  VA_ULONG,
  VA_LONGLONG,
  VA_ULONGLONG,
  VA_DOUBLE,
  VA_LONGDOUBLE,
  VA_PTR
};

/* Read `n` arguments of the types in `types` into `out`, each as the
   64 bits libcurl's printf keeps: integers widened, floating point as a
   double's bits, pointers as addresses. */
void curl_rs_va_fetch(va_list ap, const unsigned char *types, size_t n,
                      uint64_t *out)
{
  size_t i;
  for(i = 0; i < n; i++) {
    double d;
    switch(types[i]) {
    case VA_INT:
      out[i] = (uint64_t)(int64_t)va_arg(ap, int);
      break;
    case VA_UINT:
      out[i] = (uint64_t)va_arg(ap, unsigned int);
      break;
    case VA_LONG:
      out[i] = (uint64_t)(int64_t)va_arg(ap, long);
      break;
    case VA_ULONG:
      out[i] = (uint64_t)va_arg(ap, unsigned long);
      break;
    case VA_LONGLONG:
      out[i] = (uint64_t)va_arg(ap, int64_t);
      break;
    case VA_ULONGLONG:
      out[i] = va_arg(ap, uint64_t);
      break;
    case VA_DOUBLE:
      d = va_arg(ap, double);
      memcpy(&out[i], &d, sizeof(d));
      break;
    case VA_LONGDOUBLE:
      d = (double)va_arg(ap, long double);
      memcpy(&out[i], &d, sizeof(d));
      break;
    default:
      out[i] = (uint64_t)(uintptr_t)va_arg(ap, void *);
      break;
    }
  }
}
