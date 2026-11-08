#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################
#
import base64
import logging
import os
import re
import socket
import struct
import threading

import pytest
from testenv import CurlClient, Env

log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.curl_has_feature('ECH'), reason="no curl ECH support")
@pytest.mark.skipif(condition=not Env.have_nghttpx_ech(), reason="no nghttpx ECH support")
@pytest.mark.skipif(condition=not Env.have_openssl_ech(), reason="no openssl cmd ECH support")
@pytest.mark.skipif(condition=not Env.curl_is_debug(), reason="needs curl debug")
class TestECH:

    @pytest.mark.parametrize("ech_mode, exp_result, exp_exit", [
        ['false', None, 0],
        ['grease', 'sent GREASE', 0],
        ['true', 'not configured', 0],
        ['hard', None, 35]  # CURLE_SSL_CONNECT_ERROR
    ])
    def test_23_01_ech_no_config(self, env: Env, httpd, nghttpx_tcp, ech_mode, exp_result, exp_exit):
        run_env = os.environ.copy()
        curl = CurlClient(env=env, run_env=run_env)
        url = f'https://{env.domain1}:{nghttpx_tcp.port}/data.json'
        r = curl.http_download(urls=[url], with_stats=True, extra_args=[
            '--ech', ech_mode
        ])
        r.check_exit_code(exp_exit)
        if exp_exit == 0:
            r.check_stats(count=1, http_status=200, exitcode=0)
        if env.curl_uses_lib('openssl'):
            ech_result, _, _ = self._get_ech_result(r)
            assert ech_result == exp_result, f'{r.dump_logs()}'

    @pytest.mark.parametrize("ech_mode, exp_result, exp_exit", [
        ['false', None, 0],
        ['grease', 'sent GREASE', 0],
        ['true', 'succeeded', 0],
        ['hard', 'succeeded', 0]
    ])
    def test_23_02_ech_good_config(self, env: Env, httpd, nghttpx_tcp, ech_mode, exp_result, exp_exit):
        run_env = os.environ.copy()
        curl = CurlClient(env=env, run_env=run_env)
        url = f'https://{env.domain1}:{nghttpx_tcp.port}/data.json'
        ech_config = env.get_echconfig_arg(env.domain1)
        r = curl.http_download(urls=[url], with_stats=True, extra_args=[
            '--ech', ech_mode, '--ech', f'ecl:{ech_config}'
        ])
        r.check_exit_code(exp_exit)
        if exp_exit == 0:
            r.check_stats(count=1, http_status=200, exitcode=0)
        if env.curl_uses_lib('openssl'):
            ech_result, inner, outer = self._get_ech_result(r)
            assert ech_result == exp_result, f'{r.dump_logs()}'
            if ech_result == 'succeeded':
                assert inner == env.domain1, f'{r.dump_logs()}'
                assert outer == f'public.{env.domain1}', f'{r.dump_logs()}'

    @pytest.mark.parametrize("ech_mode, exp_result, exp_exit", [
        ['false', None, 0],
        ['grease', 'sent GREASE', 0],
        ['true', 'rejected', 101],  # CURLE_ECH_REQUIRED
        ['hard', 'rejected', 101]
    ])
    def test_23_03_ech_bad_config(self, env: Env, httpd, nghttpx_tcp, ech_mode, exp_result, exp_exit):
        run_env = os.environ.copy()
        curl = CurlClient(env=env, run_env=run_env)
        url = f'https://{env.domain1}:{nghttpx_tcp.port}/data.json'
        ech_config = env.get_echconfig_arg(env.domain2)
        r = curl.http_download(urls=[url], with_stats=True, extra_args=[
            '--ech', ech_mode, '--ech', f'ecl:{ech_config}'
        ])
        if env.curl_uses_lib('wolfssl'):
            # wolfssl ECH errors result in CURLE_PEER_FAILED_VERIFICATION
            exp_exit = 60 if exp_exit else 0
        elif env.curl_uses_lib('rustls-ffi'):
            # rustls ECH errors result in CURLE_SSL_CONNECT_ERROR
            exp_exit = 35 if exp_exit else 0
        r.check_exit_code(exp_exit)
        if env.curl_uses_lib('openssl'):
            ech_result, _, _ = self._get_ech_result(r)
            assert ech_result == exp_result, f'{r.dump_logs()}'

    @pytest.mark.skipif(condition=not Env.curl_uses_lib('openssl'),
                        reason="needs OpenSSL")
    @pytest.mark.parametrize("ech_mode, exp_result, pub_domain", [
        ['true', 'succeeded', 'innocent.invalid'],
        ['hard', 'succeeded', 'innocent.invalid'],
    ])
    def test_23_04_ech_outer(self, env: Env, httpd, nghttpx_tcp, ech_mode, exp_result, pub_domain):
        run_env = os.environ.copy()
        curl = CurlClient(env=env, run_env=run_env)
        url = f'https://{env.domain1}:{nghttpx_tcp.port}/data.json'
        ech_config = env.get_echconfig_arg(env.domain1)
        r = curl.http_download(urls=[url], with_stats=True, extra_args=[
            '--ech', ech_mode, '--ech', f'ecl:{ech_config}', '--ech', f'pn:{pub_domain}'
        ])
        r.check_exit_code(0)
        r.check_stats(count=1, http_status=200, exitcode=0)
        ech_result, inner, outer = self._get_ech_result(r)
        assert ech_result == exp_result, f'{r.dump_logs()}'
        assert inner == env.domain1, f'{r.dump_logs()}'
        assert outer == pub_domain, f'{r.dump_logs()}'

    def test_23_05_ech_conn_ech_reuse(self, env: Env, httpd, nghttpx_tcp):
        run_env = os.environ.copy()
        curl = CurlClient(env=env, run_env=run_env)
        url1 = f'https://{env.domain1}:{nghttpx_tcp.port}/data1.json'
        url2 = f'https://{env.domain1}:{nghttpx_tcp.port}/data2.json'
        r = curl.http_download(urls=[url1, url2], with_stats=True, url_options={
            url1: ['--ech', 'false'],
            url2: ['--ech', 'true']
        })
        r.check_exit_code(0), f'{r}'
        r.check_response(http_status=404, count=2, connect_count=2)

    def test_23_06_ech_conn_ech_config_reuse(self, env: Env, httpd, nghttpx_tcp):
        run_env = os.environ.copy()
        curl = CurlClient(env=env, run_env=run_env)
        url1 = f'https://{env.domain1}:{nghttpx_tcp.port}/data1.json'
        url2 = f'https://{env.domain1}:{nghttpx_tcp.port}/data2.json'
        ech_config = env.get_echconfig_arg(env.domain1)
        r = curl.http_download(urls=[url1, url2], with_stats=True, url_options={
            url1: ['--ech', 'true'],
            url2: ['--ech', 'true', '--ech', f'ecl:{ech_config}']
        })
        r.check_exit_code(0), f'{r}'
        r.check_response(http_status=404, count=2, connect_count=2)

    @pytest.mark.skipif(condition=not Env.curl_uses_lib('openssl'),
                        reason="needs OpenSSL")
    def test_23_07_ech_conn_ech_pub_reuse(self, env: Env, httpd, nghttpx_tcp):
        run_env = os.environ.copy()
        curl = CurlClient(env=env, run_env=run_env)
        url1 = f'https://{env.domain1}:{nghttpx_tcp.port}/data1.json'
        url2 = f'https://{env.domain1}:{nghttpx_tcp.port}/data2.json'
        r = curl.http_download(urls=[url1, url2], with_stats=True, url_options={
            url1: ['--ech', 'true'],
            url2: ['--ech', 'true', '--ech', 'pn:innocent.invalid']
        })
        r.check_exit_code(0), f'{r}'
        r.check_response(http_status=404, count=2, connect_count=2)

    def _get_ech_result(self, r):
        for line in r.trace_lines:
            m = re.search(r'ECH: result \'(.+)\' \(inner=(.+), outer=(.+)\)', line)
            if m:
                return m.group(1), m.group(2), m.group(3)
            m = re.search(r'ECH: rejected(.*)', line)
            if m:
                return 'rejected', None, None
        return None, None, None


class HttpsRecordDns(threading.Thread):
    """
    A DNS server answering A for names under `domain` with 127.0.0.1,
    AAAA with nothing and HTTPS with alpn h3 and the ECHConfigList `ech`,
    or with nothing where `ech` is None; HTTPS `delay` seconds late, so
    that it is still to come as a connection is started, and not at all if
    `silent`."""

    def __init__(self, domain: str, ech, silent: bool = False, delay: float = 0.2):
        super().__init__(daemon=True)
        self.domain = domain.encode()
        self.ech = ech
        self.silent = silent
        self.delay = delay
        self.late = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.asked = []
        self.done = False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.done = True
        self.join()
        for timer in self.late:
            timer.cancel()
            timer.join()
        self.sock.close()

    def run(self):
        while not self.done:
            try:
                query, peer = self.sock.recvfrom(4096)
            except TimeoutError:
                continue
            answer = self.answer(query)
            if answer is None:
                continue
            if self.is_https(query):
                timer = threading.Timer(self.delay, self.sock.sendto, (answer, peer))
                self.late.append(timer)
                timer.start()
            else:
                self.sock.sendto(answer, peer)

    @staticmethod
    def is_https(query):
        at = 12
        while query[at]:
            at += 1 + query[at]
        return struct.unpack('!H', query[at + 1:at + 3])[0] == 65

    def answer(self, query):
        at, labels = 12, []
        while query[at]:
            n = query[at]
            labels.append(query[at + 1:at + 1 + n])
            at += 1 + n
        at += 1
        qtype, _ = struct.unpack('!HH', query[at:at + 4])
        name = b'.'.join(labels)
        self.asked.append((name.decode(), qtype))
        answers = []
        if qtype == 65 and self.silent:
            return None
        if name.endswith(self.domain):
            if qtype == 1:
                answers.append((1, bytes([127, 0, 0, 1])))
            elif qtype == 65 and self.ech is not None:
                alpn = b'\x02h3'
                rdata = struct.pack('!H', 1) + b'\x00'
                rdata += struct.pack('!HH', 1, len(alpn)) + alpn
                rdata += struct.pack('!HH', 5, len(self.ech)) + self.ech
                answers.append((65, rdata))
        out = query[:2] + struct.pack('!HHHHH', 0x8180, 1, len(answers), 0, 0)
        out += query[12:at + 4]
        for rtype, rdata in answers:
            out += struct.pack('!HHHIH', 0xc00c, rtype, 1, 60, len(rdata)) + rdata
        return out


@pytest.mark.skipif(condition=not Env.curl_has_feature('ECH'), reason="no curl ECH support")
@pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPSRR'), reason="no HTTPSRR support")
@pytest.mark.skipif(condition=not Env.curl_uses_lib('c-ares'), reason="needs c-ares")
@pytest.mark.skipif(condition=not Env.have_nghttpx_ech(), reason="no nghttpx ECH support")
@pytest.mark.skipif(condition=not Env.have_openssl_ech(), reason="no openssl cmd ECH support")
@pytest.mark.skipif(condition=not Env.curl_is_debug(), reason="needs curl debug")
@pytest.mark.skipif(condition=not Env.have_h3(), reason="missing HTTP/3 support")
class TestECHH3:

    # ECH over HTTP/3 with the configurations of the origin's HTTPS
    # record, still to come as the QUIC attempt's socket is connected: the
    # QUIC connect waits for the record, and its ECH takes the record's
    # list, the origin's (good) or another name's (bad), or none (none),
    # which `hard` fails. A record that never comes ends at the timeout.
    @pytest.mark.parametrize("record, ech_mode, exp_exit", [
        ['good', 'true', 0], ['good', 'hard', 0],
        ['bad', 'true', 60], ['bad', 'hard', 60],  # CURLE_PEER_FAILED_VERIFICATION
        ['none', 'true', 0], ['none', 'hard', 35],  # CURLE_SSL_CONNECT_ERROR
        ['silent', 'true', 28], ['silent', 'hard', 28]  # CURLE_OPERATION_TIMEDOUT
    ])
    def test_23_08_ech_h3_record_coming(self, env: Env, httpd, nghttpx, record, ech_mode, exp_exit):
        ech = {
            'good': base64.b64decode(env.get_echconfig_arg(env.domain1)),
            'bad': base64.b64decode(env.get_echconfig_arg(env.domain2)),
            'none': None,
            'silent': None,
        }[record]
        with HttpsRecordDns(env.domain1, ech, silent=record == 'silent') as dns:
            curl = CurlClient(env=env)
            url = f'https://{env.authority_for(env.domain1, "h3")}/data.json'
            r = curl.http_download(urls=[url], alpn_proto='h3', with_stats=True, extra_args=[
                '--ech', ech_mode, '--dns-servers', f'127.0.0.1:{dns.port}',
                '--connect-timeout', '1',
                '--trace-config', 'http/3,dns,happy-eyeballs,udp'
            ])
        print(f'RESULT record={record} mode={ech_mode} exit={r.exit_code}')
        for line in r.trace_lines:
            print(f'LINE {line.rstrip()}')
        assert any(qtype == 65 and name.endswith(f'._https.{env.domain1}')
                   for name, qtype in dns.asked), f'{dns.asked}'
        r.check_exit_code(exp_exit)
        lines = [re.sub(r'^.*?\] \* ', '', line.rstrip()) for line in r.trace_lines]
        delay = '[HTTP/3] need HTTPS-RR, delaying connect'
        assert delay in lines, f'{r.dump_logs()}'
        # Said first as the attempt's socket is connected, and not once
        # the record is known.
        first = lines.index(delay)
        assert lines[first - 1].startswith('[UDP] cf_udp_connect(), opened socket='), \
            f'{r.dump_logs()}'
        known = [i for i, line in enumerate(lines) if line.startswith('HTTPS-RR ')]
        last = max(i for i, line in enumerate(lines) if line == delay)
        assert not known or last < known[0], f'{r.dump_logs()}'


@pytest.mark.skipif(condition=not Env.curl_has_feature('ECH'), reason="no curl ECH support")
@pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPSRR'), reason="no HTTPSRR support")
@pytest.mark.skipif(condition=not Env.curl_uses_lib('c-ares'), reason="needs c-ares")
@pytest.mark.skipif(condition=not Env.have_nghttpx_ech(), reason="no nghttpx ECH support")
@pytest.mark.skipif(condition=not Env.have_openssl_ech(), reason="no openssl cmd ECH support")
@pytest.mark.skipif(condition=not Env.curl_is_debug(), reason="needs curl debug")
class TestECHTcp:

    # ECH over TCP with the configurations of the origin's HTTPS record,
    # still to come as the connection is made: the TLS filter puts its
    # connect off until the record comes, saying so in its backend's words,
    # OpenSSL's (AWS-LC's, BoringSSL's) without "for ECH", wolfSSL's and
    # Rustls's with it.
    def test_23_09_ech_tcp_record_coming(self, env: Env, httpd, nghttpx_tcp):
        ech = base64.b64decode(env.get_echconfig_arg(env.domain1))
        with HttpsRecordDns(env.domain1, ech) as dns:
            curl = CurlClient(env=env)
            url = f'https://{env.domain1}:{nghttpx_tcp.port}/data.json'
            r = curl.http_download(urls=[url], with_stats=True, extra_args=[
                '--ech', 'hard', '--dns-servers', f'127.0.0.1:{dns.port}',
                '--trace-config', 'ssl,dns'
            ])
        r.check_exit_code(0)
        lines = [re.sub(r'^.*?\] \* ', '', line.rstrip()) for line in r.trace_lines]
        for_ech = env.curl_uses_lib('wolfssl') or env.curl_uses_lib('rustls-ffi')
        said = ('need HTTPS-RR for ECH, delaying connect' if for_ech
                else 'need HTTPS-RR, delaying connect')
        waits = [line for line in lines if 'need HTTPS-RR' in line]
        assert waits, f'{r.dump_logs()}'
        assert all(line == f'[SSL] {said}' for line in waits), f'{waits}'
