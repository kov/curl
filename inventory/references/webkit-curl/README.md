# WebKit's libcurl backend (reference)

WebKit's network backend for curl ports, `Source/WebCore/platform/network/curl/`, copied
unchanged from https://github.com/WebKit/WebKit at commit
03a5f11b02d61daf046764ce8c634182dec399eb (main, fetched 2026-10-22; the directory's last change
is 4b3653d2ed3c). Each file keeps its own BSD-2-Clause licence header.

It is a real, large application of libcurl, kept here as evidence when a decision turns on how
applications use the C API (what they rely on beyond the documented contract), alongside the
corpus of command lines for the tool. It is not built or compiled.

What it relies on, found so far:
- `CURLOPT_HTTPHEADER`/`CURLOPT_PROXYHEADER` set once, after the first `curl_slist_append`, with
  later headers appended in place: libcurl must read the list when it builds the request
  (`CurlContext.cpp`, `CurlHandle::appendRequestHeader`).
- Handles set up on one thread and added to a multi on another; one share (COOKIE, DNS,
  SSL_SESSION) with lock functions used across threads; `curl_multi_wakeup` from other threads.
- `CURLOPT_CONNECT_ONLY` for WebSocket streams (`CurlStream.cpp`).
- No `CURLOPT_FOLLOWLOCATION`: it follows redirects itself.
