#!/bin/sh
# Runs a command without this container's proxy variables, which the library under test reads,
# with the HTTP/2 test server's nghttpx bound to IPv4 (no IPv6 here) and USER set for pytest.
exec env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u no_proxy -u NO_PROXY -u all_proxy -u ALL_PROXY \
  NGHTTPX=/usr/local/bin/nghttpx-v4 USER="${USER:-root}" "$@"
