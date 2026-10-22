//! The tool running HTTP transfers: the options that shape the request
//! and what is done with the response.
//!
//! The expectations are the C tool's: `CURL_TOOL_UNDER_TEST` names
//! another tool to run them on, as
//! `CURL_TOOL_UNDER_TEST=build/c/src/curl LD_LIBRARY_PATH=build/c/lib`.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::thread::JoinHandle;

/// Each connection's replies, one for each request on it.
type Script = Vec<Vec<Vec<u8>>>;

/// A server that answers one request with `reply`, then closes; joining
/// it gives the request it got, its port written as `PORT`.
struct Server {
    port: u16,
    request: JoinHandle<Vec<u8>>,
}

impl Server {
    fn new(reply: &'static [u8]) -> Server {
        Server::script(vec![vec![reply.to_vec()]])
    }

    /// A server that takes a connection for each of `conns` in turn,
    /// answers each request on it with the connection's next reply, then
    /// closes it; joining it gives the requests, one after another.
    fn script(conns: Script) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let request = std::thread::spawn(move || {
            let mut all = Vec::new();
            for replies in conns {
                let Ok((mut peer, _)) = listener.accept() else {
                    break;
                };
                for reply in replies {
                    let mut got = Vec::new();
                    let mut buf = [0; 4096];
                    while !request_ended(&got) {
                        match peer.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => got.extend_from_slice(&buf[..n]),
                        }
                    }
                    all.extend_from_slice(&got);
                    let _ = peer.write_all(&reply);
                }
            }
            String::from_utf8_lossy(&all)
                .replace(&port.to_string(), "PORT")
                .into_bytes()
        });
        Server { port, request }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }

    fn request(self) -> String {
        String::from_utf8(self.request.join().unwrap()).unwrap()
    }
}

/// Whether `got` holds a whole request: its head, and the body its
/// Content-Length or chunked coding says.
fn request_ended(got: &[u8]) -> bool {
    let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
    let body = &got[end + 4..];
    if head.contains("\r\ntransfer-encoding: chunked") {
        return body.ends_with(b"0\r\n\r\n");
    }
    let length = head
        .split("\r\n")
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0);
    body.len() >= length
}

struct Run {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}

/// Run the tool with `args`, without a configuration file.
fn curl(args: &[&str]) -> Run {
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let out = Command::new(tool).arg("-q").args(args).output().unwrap();
    Run {
        code: out.status.code().unwrap(),
        stdout: out.stdout,
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nA: b\r\n\r\n-foo-\n";

/// `-A`, `-e` (its `;auto` cut), `-H` adding, replacing and removing,
/// and `-0`, as they reach the request.
#[test]
fn options_shape_the_request() {
    let s = Server::new(OK);
    let url = s.url();
    let run = curl(&[
        "-s",
        "-A",
        "me/1",
        "-e",
        "http://r/;auto",
        "-H",
        "X-A: 1",
        "-H",
        "Accept;",
        "-0",
        &url,
    ]);
    assert_eq!((run.code, &run.stdout[..]), (0, &b"-foo-\n"[..]));
    assert_eq!(
        s.request(),
        "GET / HTTP/1.0\r\nHost: 127.0.0.1:PORT\r\nUser-Agent: me/1\r\nReferer: http://r/\r\n\
         X-A: 1\r\nAccept:\r\n\r\n"
    );
}

/// `-i` shows the header lines before the body, and `-I` them alone.
#[test]
fn shows_the_headers_of_http() {
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nA: b\r\n\r\n";
    let s = Server::new(OK);
    let run = curl(&["-s", "-i", &s.url()]);
    assert_eq!(run.stdout, [&head[..], b"-foo-\n"].concat());
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nA: b\r\n\r\n");
    let run = curl(&["-s", "-I", &s.url()]);
    assert_eq!((run.code, &run.stdout[..]), (0, &head[..]));
    assert!(s.request().starts_with("HEAD / HTTP/1.1\r\n"));
}

/// `-D` writes the header lines, and only those, to its file.
#[test]
fn dumps_the_headers() {
    let dir = std::env::temp_dir().join(format!("curl-tool-http-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("heads");
    let s = Server::new(OK);
    let run = curl(&["-s", "-D", file.to_str().unwrap(), &s.url()]);
    assert_eq!((run.code, &run.stdout[..]), (0, &b"-foo-\n"[..]));
    assert_eq!(
        std::fs::read(&file).unwrap(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nA: b\r\n\r\n"
    );
    std::fs::remove_dir_all(&dir).unwrap();
    // One that cannot be opened fails the transfer before it starts.
    let missing = dir.join("no/such/heads");
    let run = curl(&[
        "-sS",
        "-D",
        missing.to_str().unwrap(),
        "http://127.0.0.1:1/",
    ]);
    assert_eq!(run.code, 23);
    assert_eq!(
        run.stderr,
        format!(
            "curl: Failed to open {}\n\
             curl: (23) Failed writing received data to disk/application\n",
            missing.display()
        )
    );
}

/// `-f` fails a 404, with what the library says, writing no body.
#[test]
fn fails_on_an_error_code() {
    let s = Server::new(b"HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\n\r\nabcde");
    let run = curl(&["-sS", "-f", &s.url()]);
    assert_eq!(
        (run.code, &run.stdout[..], &run.stderr[..]),
        (
            22,
            &b""[..],
            "curl: (22) The requested URL returned error: 404\n"
        )
    );
}

/// `--fail-with-body` writes the error response's body, then fails.
#[test]
fn fails_on_an_error_code_after_its_body() {
    let s = Server::new(b"HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\n\r\nabcde");
    let run = curl(&["-sS", "--fail-with-body", &s.url()]);
    assert_eq!(
        (run.code, &run.stdout[..], &run.stderr[..]),
        (
            22,
            &b"abcde"[..],
            "curl: (22) The requested URL returned error: 404\n"
        )
    );
}

/// `--max-filesize` takes a unit; a body announced larger fails at once.
#[test]
fn limits_the_file_size() {
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 2000\r\n\r\nabc");
    let run = curl(&["-sS", "--max-filesize", "1k", &s.url()]);
    assert_eq!(
        (run.code, &run.stderr[..]),
        (63, "curl: (63) Maximum file size exceeded\n")
    );
}

/// `-m` ends a transfer that takes too long, counted from its start.
#[test]
fn gives_up_after_the_time_allowed() {
    // Connected by the backlog, never answered.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}/", silent.local_addr().unwrap().port());
    let started = std::time::Instant::now();
    let run = curl(&["-sS", "-m", "0.3", &url]);
    let took = started.elapsed();
    assert_eq!(run.code, 28, "{}", run.stderr);
    assert!(
        run.stderr
            .starts_with("curl: (28) Operation timed out after 3")
            && run
                .stderr
                .ends_with(" milliseconds with 0 bytes received\n"),
        "{}",
        run.stderr
    );
    assert!(took < std::time::Duration::from_secs(5), "{took:?}");
}

/// `-I` with `-T` asks for two methods: the transfer is not made.
#[test]
fn takes_one_method() {
    let run = curl(&["-I", "-T", "/dev/null", "http://127.0.0.1:1/"]);
    assert_eq!(run.code, 2);
    assert_eq!(
        run.stderr,
        "Warning: You can only select one HTTP request method! You asked for both PUT \n\
         Warning: (-T, --upload-file) and HEAD (-I, --head).\n"
    );
    let run = curl(&["-d", "x", "-T", "/dev/null", "http://127.0.0.1:1/"]);
    assert_eq!(run.code, 2);
    assert_eq!(
        run.stderr,
        "Warning: You can only select one HTTP request method! You asked for both PUT \n\
         Warning: (-T, --upload-file) and POST (-d, --data).\n"
    );
}

/// `-d` and its kin join their data with `&` into a POST's body, typed
/// as a form; `--data-urlencode` encodes, its spaces as `+`.
#[test]
fn posts_the_data_given() {
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let run = curl(&[
        "-sS",
        "-d",
        "a=b",
        "--data-raw",
        "@c d",
        "--data-urlencode",
        "n=x y&",
        &s.url(),
    ]);
    assert_eq!((run.code, &run.stderr[..]), (0, ""));
    let request = s.request();
    assert!(request.starts_with("POST / HTTP/1.1\r\n"), "{request}");
    let body = "a=b&@c d&n=x+y%26";
    assert!(
        request.ends_with(&format!(
            "Content-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{body}",
            body.len()
        )),
        "{request}"
    );
}

/// `-T -` sends standard input, chunked as its size is not known.
#[test]
fn uploads_standard_input() {
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let mut child = Command::new(tool)
        .args(["-q", "-sS", "-T", "-", "-H", "Expect:", &s.url()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"hello").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let request = s.request();
    assert!(request.starts_with("PUT / HTTP/1.1\r\n"), "{request}");
    assert!(
        request.ends_with("Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
        "{request}"
    );
}

/// A redirect that has `-T -` send its body again cannot, from a pipe:
/// the seek fails, and the library says so after the tool's reason.
#[test]
fn cannot_send_piped_standard_input_again() {
    let s = Server::new(b"HTTP/1.1 307 Again\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n");
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let mut child = Command::new(tool)
        .args(["-q", "-sSv", "-L", "-T", "-", "-H", "Expect:", &s.url()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"hello").unwrap();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(65), "{stderr}");
    assert!(
        stderr.contains(
            "\n* seek callback returned error 2\n\
             * rewind of client reader 'cr-in' failed: 65\n"
        ),
        "{stderr}"
    );
    assert!(
        stderr.ends_with("\ncurl: (65) seek callback returned error 2\n"),
        "{stderr}"
    );
}

/// `-X` sends its method, noting when it is the one implied; data is
/// not resumed.
#[test]
fn sends_the_method_asked_for() {
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let run = curl(&[
        "-v",
        "--no-progress-meter",
        "-X",
        "POST",
        "-d",
        "x",
        &s.url(),
    ]);
    assert_eq!(run.code, 0);
    assert!(
        run.stderr
            .starts_with("Note: Unnecessary use of -X or --request, POST is already inferred.\n"),
        "{}",
        run.stderr
    );
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let run = curl(&["-sS", "-X", "DELETE", &s.url()]);
    assert_eq!((run.code, &run.stderr[..]), (0, ""));
    assert!(s.request().starts_with("DELETE / HTTP/1.1\r\n"));
    let run = curl(&["-d", "x", "-C", "-", "http://127.0.0.1:1/"]);
    assert_eq!(
        (run.code, &run.stderr[..]),
        (43, "curl: (43) HTTP upload cannot be resumed\n")
    );
}

/// `--json` types the request and accepts JSON unless `-H` says
/// otherwise, and joins its data with nothing.
#[test]
fn posts_json() {
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let run = curl(&[
        "-sS",
        "--json",
        "{",
        "--json",
        "}",
        "-H",
        "accept: text/x",
        &s.url(),
    ]);
    assert_eq!(run.code, 0);
    let request = s.request();
    assert!(
        request.contains("\r\naccept: text/x\r\nContent-Type: application/json\r\n"),
        "{request}"
    );
    assert!(!request.contains("Accept: application/json"), "{request}");
    assert!(request.ends_with("\r\n\r\n{}"), "{request}");
}

/// `-H` warns of a header with neither colon nor semicolon, and a second
/// HTTP version option warns that it overrides the first.
#[test]
fn warns_of_odd_header_and_version_options() {
    let warning = "Warning: The provided HTTP header 'foo' does not look like a header?\n";
    let overrides = "Warning: Overrides previous HTTP version option\n";
    for (args, want) in [
        (&["-H", "foo"][..], warning.to_owned()),
        (&["-H", "a:b", "-H", "c;"], String::new()),
        (&["-0", "--http1.1"], overrides.to_owned()),
        (&["-0", "-0"], String::new()),
    ] {
        // No transfer: the URL's port refuses.
        let mut all = vec!["--no-progress-meter", "-o", "/dev/null"];
        all.extend_from_slice(args);
        all.push("http://127.0.0.1:1/");
        let run = curl(&all);
        if want.is_empty() {
            assert!(!run.stderr.contains("Warning"), "{args:?}: {}", run.stderr);
        } else {
            assert!(run.stderr.starts_with(&want), "{args:?}: {}", run.stderr);
        }
    }
}

/// `-D -` dumps the header lines to standard output, `-D %` to standard
/// error.
#[test]
fn dumps_the_headers_to_the_standard_streams() {
    let head = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nA: b\r\n\r\n";
    let s = Server::new(OK);
    let run = curl(&["-s", "-D", "-", &s.url()]);
    assert_eq!(run.stdout, [head.as_bytes(), b"-foo-\n"].concat());
    let s = Server::new(OK);
    let run = curl(&["-s", "-D", "%", &s.url()]);
    assert_eq!((&run.stdout[..], &run.stderr[..]), (&b"-foo-\n"[..], head));
}

/// With two URLs, `-D` starts its file afresh for the first transfer and
/// adds the second's header lines after.
#[test]
fn dumps_the_headers_of_each_transfer() {
    let dir = std::env::temp_dir().join(format!("curl-tool-heads-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("heads");
    std::fs::write(&file, "old\n").unwrap();
    let (a, b) = (Server::new(OK), Server::new(OK));
    let run = curl(&["-s", "-D", file.to_str().unwrap(), &a.url(), &b.url()]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let head = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nA: b\r\n\r\n";
    assert_eq!(std::fs::read(&file).unwrap(), [&head[..], head].concat());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A directory of its own for a test, emptied.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("curl-tool-http-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `-c` saves the cookies the server set once the transfer is done; a
/// jar that cannot be written goes unsaid, as C traces nothing after its
/// transfer is cleaned up.
#[test]
fn saves_the_cookie_jar() {
    let dir = scratch("jar");
    let jar = dir.join("jar");
    let set = b"HTTP/1.1 200 OK\r\nSet-Cookie: n=v\r\nContent-Length: 0\r\n\r\n";
    let s = Server::new(set);
    let run = curl(&["-sS", "-c", jar.to_str().unwrap(), &s.url()]);
    assert_eq!((run.code, &run.stderr[..]), (0, ""));
    let saved = String::from_utf8(std::fs::read(&jar).unwrap()).unwrap();
    assert!(
        saved.ends_with("\n127.0.0.1\tFALSE\t/\tFALSE\t0\tn\tv\n"),
        "{saved}"
    );
    let s = Server::new(set);
    let run = curl(&["-sv", "-c", "/nonexistent/dir/jar", &s.url()]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stderr.contains("* Added cookie n=\"v\""),
        "{}",
        run.stderr
    );
    assert!(!run.stderr.contains("save cookies"), "{}", run.stderr);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `-b` strings are joined by `;`, and a blank unless the next starts
/// with one; together they may be 8199 bytes at most.
#[test]
fn joins_the_cookies_given() {
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let run = curl(&[
        "-sS",
        "-b",
        "a=1",
        "-b",
        "b=2",
        "-b",
        " c=3",
        "-b",
        "\tc=4",
        &s.url(),
    ]);
    assert_eq!((run.code, &run.stderr[..]), (0, ""));
    let request = s.request();
    assert!(
        request.contains("\r\nCookie: a=1; b=2; c=3;\tc=4\r\n"),
        "{request}"
    );
    let most = format!("a={}", "x".repeat(8197));
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let run = curl(&["-sS", "-b", &most, &s.url()]);
    assert_eq!((run.code, &run.stderr[..]), (0, ""));
    assert!(s.request().contains(&format!("\r\nCookie: {most}\r\n")));
    let run = curl(&["-b", &format!("{most}x"), "http://127.0.0.1:1/"]);
    assert_eq!(
        (run.code, &run.stderr[..]),
        (
            100,
            "Warning: skipped provided cookie, the cookie header would go over 8200 bytes\n\
             curl: (100) A value or data field grew larger than allowed\n"
        )
    );
}

/// What `--retry` does with a download it resumes (`-C -`): what an
/// attempt wrote is kept, and the rest asked for, when the response says
/// a range may be asked for (`Accept-Ranges: bytes`) or answers a range
/// asked for; otherwise it is thrown away and the whole asked for again.
#[test]
fn resumes_a_retried_download() {
    let retry = [
        "-sS",
        "-C",
        "-",
        "--retry",
        "1",
        "--retry-all-errors",
        "--retry-delay",
        "0.01",
    ];
    let partial = |head: &str, body: &str| format!("{head}\r\n\r\n{body}").into_bytes();
    let rest = partial(
        "HTTP/1.1 206 Partial\r\nContent-Range: bytes 5-9/10\r\nContent-Length: 5",
        "56789",
    );
    let whole = partial("HTTP/1.1 200 OK\r\nContent-Length: 10", "0123456789");
    let cases = [
        // The first response, and the file there before, if any.
        (
            "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nContent-Length: 10",
            "01234",
            None,
            Some("bytes=5-"),
        ),
        (
            "HTTP/1.1 200 OK\r\nAccept-Ranges: none\r\nContent-Length: 10",
            "01234",
            None,
            None,
        ),
        (
            "HTTP/1.1 206 Partial\r\nContent-Range: bytes 2-9/10\r\nContent-Length: 8",
            "234",
            Some("01"),
            Some("bytes=5-"),
        ),
        // A range not asked for is no range.
        (
            "HTTP/1.1 206 Partial\r\nContent-Range: bytes 0-9/10\r\nContent-Length: 10",
            "01234",
            None,
            None,
        ),
    ];
    let dir = scratch("resume");
    for (i, (head, body, before, again)) in cases.into_iter().enumerate() {
        let out = dir.join(format!("out{i}"));
        if let Some(before) = before {
            std::fs::write(&out, before).unwrap();
        }
        let second = match again {
            Some(_) => rest.clone(),
            None => whole.clone(),
        };
        let s = Server::script(vec![vec![partial(head, body)], vec![second]]);
        let mut args = retry.to_vec();
        args.extend(["-o", out.to_str().unwrap()]);
        let url = s.url();
        args.push(&url);
        let run = curl(&args);
        assert_eq!(
            (run.code, &run.stderr[..]),
            (0, "curl: (18) end of response with 5 bytes missing\n"),
            "{head}"
        );
        assert_eq!(std::fs::read(&out).unwrap(), b"0123456789", "{head}");
        let requests = s.request();
        let ranges: Vec<_> = requests
            .lines()
            .filter_map(|l| l.strip_prefix("Range: "))
            .collect();
        let first = before.map(|b| format!("bytes={}-", b.len()));
        let want: Vec<_> = first.as_deref().into_iter().chain(again).collect();
        assert_eq!(ranges, want, "{head}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A response that says to try again waits as its `Retry-After:` says,
/// over `--retry-delay`, unless that would go past `--retry-max-time`;
/// without either, the first wait is a second.
#[test]
fn waits_as_the_server_says() {
    let busy =
        |after: &str| format!("HTTP/1.1 503 Busy\r\n{after}Content-Length: 0\r\n\r\n").into_bytes();
    let fine = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n".to_vec();
    let waited = "Warning: Problem : HTTP error. Retrying in 1 second. 1 retry left.\n";
    let s = Server::script(vec![vec![busy("Retry-After: 1\r\n")], vec![fine.clone()]]);
    let run = curl(&[
        "--no-progress-meter",
        "--retry",
        "1",
        "--retry-delay",
        "0.01",
        &s.url(),
    ]);
    assert_eq!(
        (run.code, &run.stdout[..], &run.stderr[..]),
        (0, &b"ok\n"[..], waited)
    );
    let s = Server::script(vec![vec![busy("")], vec![fine]]);
    let run = curl(&["--no-progress-meter", "--retry", "1", &s.url()]);
    assert_eq!(
        (run.code, &run.stdout[..], &run.stderr[..]),
        (0, &b"ok\n"[..], waited)
    );
    let s = Server::script(vec![vec![busy("Retry-After: 2\r\n")]]);
    let run = curl(&[
        "--no-progress-meter",
        "--retry",
        "1",
        "--retry-max-time",
        "1",
        "-w",
        "%{http_code} %{num_retries}",
        &s.url(),
    ]);
    assert_eq!(
        (run.code, &run.stdout[..], &run.stderr[..]),
        (
            0,
            &b"503 0"[..],
            "Warning: The Retry-After: time would make this command line exceed the maximum \n\
             Warning: allowed time for retries.\n"
        )
    );
}

/// `--fail-with-body` adds its failure only to a transfer that did not
/// fail already, or failed unsaid (`-s`).
#[test]
fn fails_with_body_unless_failed_already() {
    let too_big = b"HTTP/1.1 404 Nope\r\nContent-Length: 6\r\n\r\nabcdef";
    for (quiet, code, said) in [
        (None, 63, "curl: (63) Maximum file size exceeded\n"),
        (Some("-sS"), 63, "curl: (63) Maximum file size exceeded\n"),
        (Some("-s"), 22, ""),
    ] {
        let s = Server::new(too_big);
        let url = s.url();
        let mut args = vec![
            "--no-progress-meter",
            "--fail-with-body",
            "--max-filesize",
            "2",
        ];
        args.extend(quiet);
        args.push(&url);
        let run = curl(&args);
        assert_eq!((run.code, &run.stderr[..]), (code, said), "{quiet:?}");
    }
}

/// `--haproxy-protocol` starts the connection with a PROXY line, which
/// `--haproxy-clientip` alone also sends, with its address.
#[test]
fn sends_a_proxy_protocol_line() {
    for (args, from) in [
        (&["--haproxy-protocol"][..], "127.0.0.1 127.0.0.1"),
        (&["--haproxy-clientip", "10.1.2.3"], "10.1.2.3 10.1.2.3"),
    ] {
        let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let url = s.url();
        let mut all = vec!["-sS"];
        all.extend_from_slice(args);
        all.push(&url);
        let run = curl(&all);
        assert_eq!((run.code, &run.stderr[..]), (0, ""));
        let request = s.request();
        assert!(
            request.starts_with(&format!("PROXY TCP4 {from} ")) && request.contains("\r\nGET / "),
            "{request}"
        );
    }
}

/// `-i` shows a tunnel's CONNECT response before the response through it,
/// unless `--suppress-connect-headers`.
#[test]
fn shows_the_connect_response_unless_suppressed() {
    let tunnel = || {
        Server::script(vec![vec![
            b"HTTP/1.1 200 Connection established\r\nX-P: 1\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n".to_vec(),
        ]])
    };
    let through = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n";
    for (suppress, shown) in [
        (
            false,
            &b"HTTP/1.1 200 Connection established\r\nX-P: 1\r\n\r\n"[..],
        ),
        (true, b""),
    ] {
        let s = tunnel();
        let proxy = s.url();
        let mut args = vec!["-sS", "-i", "-p", "-x", &proxy];
        if suppress {
            args.push("--suppress-connect-headers");
        }
        args.push("http://target.invalid/");
        let run = curl(&args);
        assert_eq!((run.code, &run.stderr[..]), (0, ""));
        assert_eq!(run.stdout, [shown, through].concat(), "{suppress}");
        assert!(
            s.request()
                .starts_with("CONNECT target.invalid:80 HTTP/1.1\r\n")
        );
    }
}

/// `--netrc-file` alone reads its file for the login; `-u` sends one,
/// basic.
#[test]
fn logs_in_as_told() {
    let dir = scratch("netrc");
    let netrc = dir.join("netrc");
    std::fs::write(&netrc, "machine 127.0.0.1 login me password pw\n").unwrap();
    for (args, auth) in [
        (vec!["--netrc-file", netrc.to_str().unwrap()], "bWU6cHc="),
        (vec!["-u", "a:b"], "YTpi"),
    ] {
        let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let url = s.url();
        let mut all = vec!["-sS"];
        all.extend(args);
        all.push(&url);
        let run = curl(&all);
        assert_eq!((run.code, &run.stderr[..]), (0, ""));
        let request = s.request();
        assert!(
            request.contains(&format!("\r\nAuthorization: Basic {auth}\r\n")),
            "{request}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `--resolve` gives a name its address.
#[test]
fn resolves_as_told() {
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n");
    let to = format!("nosuch.invalid:{}:127.0.0.1", s.port);
    let url = format!("http://nosuch.invalid:{}/", s.port);
    let run = curl(&["-sS", "--resolve", &to, &url]);
    assert_eq!(
        (run.code, &run.stdout[..], &run.stderr[..]),
        (0, &b"ok\n"[..], "")
    );
    assert!(s.request().contains("\r\nHost: nosuch.invalid:PORT\r\n"));
}

/// `--compressed` asks for the codings this build undoes, and undoes
/// them.
#[test]
fn undoes_a_compressed_response() {
    // "hello\n", gzipped.
    let gzipped = [
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
        0xe7, 0x02, 0x00, 0x20, 0x30, 0x3a, 0x36, 0x06, 0x00, 0x00, 0x00,
    ];
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
        gzipped.len()
    );
    let s = Server::script(vec![vec![[head.as_bytes(), &gzipped].concat()]]);
    let run = curl(&["-sS", "--compressed", &s.url()]);
    assert_eq!(
        (run.code, &run.stdout[..], &run.stderr[..]),
        (0, &b"hello\n"[..], "")
    );
    assert!(s.request().contains("\r\nAccept-Encoding: "));
}

/// `-J` names the file `-O` saves as the response's
/// `Content-Disposition:` says; a name `-o` gives is kept, and `-O`
/// alone takes the URL's.
#[test]
fn names_a_remote_file_as_the_server_says() {
    let named = b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename= \"cd-name\"\r\n\
                  Content-Length: 3\r\n\r\nok\n";
    let dir = scratch("remote-name");
    let at = dir.to_str().unwrap();
    let given = dir.join("given");
    for (args, file) in [
        (vec!["-O", "-J", "--output-dir", at], "cd-name"),
        (vec!["-J", "-o", given.to_str().unwrap()], "given"),
        (vec!["-O", "--output-dir", at], "url-name"),
    ] {
        let s = Server::new(named);
        let url = format!("{}url-name", s.url());
        let mut all = vec!["-sS"];
        all.extend(&args);
        all.push(&url);
        let run = curl(&all);
        assert_eq!((run.code, &run.stderr[..]), (0, ""), "{args:?}");
        let files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(files, [file], "{args:?}");
        assert_eq!(std::fs::read(dir.join(file)).unwrap(), b"ok\n");
        std::fs::remove_file(dir.join(file)).unwrap();
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A body sent after `Expect: 100-continue` waits a second for the 100
/// that does not come, or as long as `--expect100-timeout` says.
#[test]
fn waits_for_a_continue_as_long_as_told() {
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    for (wait, at_least, below) in [(None, 900, 3000), (Some("0.1"), 0, 700)] {
        let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let url = s.url();
        let mut args = vec!["-q", "-sS", "-T", "-"];
        if let Some(wait) = wait {
            args.extend(["--expect100-timeout", wait]);
        }
        args.push(&url);
        let started = std::time::Instant::now();
        let mut child = Command::new(&tool)
            .args(&args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"hello").unwrap();
        let out = child.wait_with_output().unwrap();
        let took = started.elapsed().as_millis();
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!((at_least..below).contains(&took), "{wait:?}: {took} ms");
        assert!(s.request().contains("\r\nExpect: 100-continue\r\n"));
    }
}

/// What `-O -J` saves a response as, and with `-i` what it writes:
/// `Content-Disposition:` without a file name leaves the URL's, a 3xx's
/// `Location:` names the file until then, and the lines shown before the
/// name is known wait for it.
#[test]
fn reads_the_name_the_server_gives_as_c_does() {
    let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n".to_vec();
    let disposed = |value: &str| {
        format!("HTTP/1.1 200 OK\r\nContent-Disposition: {value}\r\nContent-Length: 3\r\n\r\nok\n")
            .into_bytes()
    };
    let moved = |code: u16| {
        format!(
            "HTTP/1.1 {code} Moved\r\nLocation: moved-name\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n"
        )
        .into_bytes()
    };
    let interim = [
        &b"HTTP/1.1 100 Continue\r\n\r\n"[..],
        b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=cd-name\r\n",
        b"Content-Length: 3\r\n\r\nok\n",
    ]
    .concat();
    let cases: [(Script, bool, &str, &[u8]); 7] = [
        (vec![vec![disposed("inline")]], false, "url-name", b"ok\n"),
        (
            vec![vec![disposed("abcdefghijk")]],
            false,
            "url-name",
            b"ok\n",
        ),
        (
            vec![vec![disposed("abcdefghij;   ")]],
            false,
            "url-name",
            b"ok\n",
        ),
        (
            vec![vec![moved(301)], vec![ok.clone()]],
            false,
            "moved-name",
            b"ok\n",
        ),
        (vec![vec![moved(200)]], false, "url-name", b""),
        (vec![vec![interim.clone()]], true, "cd-name", &interim),
        // Without a body, what was held when the file was made is all.
        (
            vec![vec![
                b"HTTP/1.1 200 OK\r\nContent-Disposition: inline\r\nContent-Length: 0\r\n\r\n"
                    .to_vec(),
            ]],
            true,
            "url-name",
            b"HTTP/1.1 200 OK\r\n",
        ),
    ];
    let dir = scratch("server-names");
    let at = dir.to_str().unwrap();
    for (i, (script, show, file, content)) in cases.into_iter().enumerate() {
        let s = Server::script(script);
        let url = format!("{}url-name", s.url());
        let mut args = vec!["-sS", "-L", "-O", "-J", "--output-dir", at];
        if show {
            args.push("-i");
        }
        args.push(&url);
        let run = curl(&args);
        assert_eq!((run.code, &run.stderr[..]), (0, ""), "{i}");
        let files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(files, [file], "{i}");
        assert_eq!(
            String::from_utf8_lossy(&std::fs::read(dir.join(file)).unwrap()),
            String::from_utf8_lossy(content),
            "{i}"
        );
        std::fs::remove_file(dir.join(file)).unwrap();
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Run the tool with `args` and `typed` on standard input, outside any
/// terminal: `setsid` leaves it without one, so a password asked for is
/// read from standard input (`/dev/tty` would wait for a person).
fn curl_typing(args: &[&str], typed: &[u8]) -> Run {
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let mut child = Command::new("setsid")
        .arg("-w")
        .arg(tool)
        .args(["-q", "-sS"])
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // One write, so one read takes all of it.
    child.stdin.take().unwrap().write_all(typed).unwrap();
    let out = child.wait_with_output().unwrap();
    Run {
        code: out.status.code().unwrap(),
        stdout: out.stdout,
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

/// The `Authorization` and `Proxy-Authorization` lines of `request`.
fn logins(request: &str) -> Vec<&str> {
    request
        .split("\r\n")
        .filter(|line| line.contains("Authorization: "))
        .collect()
}

const CLOSED: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// A `-u` or `-U` without a password asks for one on standard error and
/// takes one read of standard input, its last byte cut, up to a zero
/// byte; options after the user stay. `;options` alone, a password,
/// even empty, and `--oauth2-bearer` ask for none.
#[test]
fn asks_for_a_missing_password() {
    /// The arguments, what is typed, the prompts, the logins sent.
    type Case = (
        &'static [&'static str],
        &'static [u8],
        &'static str,
        &'static [&'static str],
    );
    let host = "Enter host password for user 'bob':\n";
    let cases: [Case; 9] = [
        (
            &["-u", "bob"],
            b"secret\n",
            host,
            &["Authorization: Basic Ym9iOnNlY3JldA=="],
        ),
        // bob;opt:secret
        (
            &["-u", "bob;opt"],
            b"secret\n",
            host,
            &["Authorization: Basic Ym9iO29wdDpzZWNyZXQ="],
        ),
        // ;x:
        (
            &["-u", ";x"],
            b"secret\n",
            "",
            &["Authorization: Basic O3g6"],
        ),
        // bob:
        (
            &["-u", "bob:"],
            b"secret\n",
            "",
            &["Authorization: Basic Ym9iOg=="],
        ),
        (
            &["-u", "bob"],
            b"",
            host,
            &["Authorization: Basic Ym9iOg=="],
        ),
        // bob:secre
        (
            &["-u", "bob"],
            b"secret",
            host,
            &["Authorization: Basic Ym9iOnNlY3Jl"],
        ),
        // bob:se
        (
            &["-u", "bob"],
            b"se\0cret\n",
            host,
            &["Authorization: Basic Ym9iOnNl"],
        ),
        (
            &["-u", "bob", "--oauth2-bearer", "tok"],
            b"secret\n",
            "",
            &["Authorization: Bearer tok"],
        ),
        // The first read takes both lines: bob:a\nb, then pete:.
        (
            &[
                "-u",
                "bob",
                "-x",
                "URL",
                "-U",
                "pete",
                "http://example.invalid/",
            ],
            b"a\nb\n",
            "Enter host password for user 'bob':\nEnter proxy password for user 'pete':\n",
            &[
                "Proxy-Authorization: Basic cGV0ZTo=",
                "Authorization: Basic Ym9iOmEKYg==",
            ],
        ),
    ];
    for (i, (args, typed, prompts, sent)) in cases.into_iter().enumerate() {
        let s = Server::new(CLOSED);
        let url = s.url();
        let mut all: Vec<&str> = args
            .iter()
            .map(|&a| if a == "URL" { &url[..] } else { a })
            .collect();
        if !args.contains(&"-x") {
            all.push(&url);
        }
        let run = curl_typing(&all, typed);
        assert_eq!((run.code, &run.stderr[..]), (0, prompts), "{i}");
        assert_eq!(logins(&s.request()), sent, "{i}");
    }
}

/// The prompt is an operation's, not a URL's: one for all the URLs of
/// one, numbered when `--next` makes several, and all asked before the
/// first transfer.
#[test]
fn asks_for_each_operation_s_password() {
    let cases: [(&[&str], &str, &[&str]); 3] = [
        (
            &["-u", "bob", "URL", "URL"],
            "Enter host password for user 'bob':\n",
            &[
                "Authorization: Basic Ym9iOnNlY3JldA==",
                "Authorization: Basic Ym9iOnNlY3JldA==",
            ],
        ),
        (
            &["-u", "bob", "URL", "--next", "URL"],
            "Enter host password for user 'bob' on URL #1:\n",
            &["Authorization: Basic Ym9iOnNlY3JldA=="],
        ),
        (
            &[
                "URL",
                "--next",
                "-U",
                "pete",
                "-x",
                "URL",
                "http://example.invalid/",
            ],
            "Enter proxy password for user 'pete' on URL #2:\n",
            &["Proxy-Authorization: Basic cGV0ZTpzZWNyZXQ="],
        ),
    ];
    for (i, (args, prompts, sent)) in cases.into_iter().enumerate() {
        let s = Server::script(vec![vec![CLOSED.to_vec()], vec![CLOSED.to_vec()]]);
        let url = s.url();
        let all: Vec<&str> = args
            .iter()
            .map(|&a| if a == "URL" { &url[..] } else { a })
            .collect();
        let run = curl_typing(&all, b"secret\n");
        assert_eq!((run.code, &run.stderr[..]), (0, prompts), "{i}");
        assert_eq!(logins(&s.request()), sent, "{i}");
    }
    // Asked before the first operation finds it has no URL; the help
    // line after differs with the manual built in.
    let run = curl_typing(&["-u", "bob"], b"secret\n");
    assert_eq!(run.code, 2);
    assert!(
        run.stderr
            .starts_with("Enter host password for user 'bob':\ncurl: (2) no URL specified\n"),
        "{}",
        run.stderr
    );
}

/// The prompt is cut at 255 bytes; a password typed past 2047 bytes is
/// cut there; and a login that would reach 100 KiB fails the run, as
/// out of memory and without a word.
#[test]
fn bounds_the_password_asked_for() {
    let s = Server::new(CLOSED);
    let url = s.url();
    let user = "u".repeat(300);
    let mut typed = vec![b'p'; 3000];
    typed.push(b'\n');
    let run = curl_typing(&["-u", &user, &url], &typed);
    let prompt = format!("Enter host password for user '{user}");
    assert_eq!(
        (run.code, &run.stderr[..]),
        (0, &format!("{}\n", &prompt[..255])[..])
    );
    let request = s.request();
    let sent = logins(&request);
    assert_eq!(sent.len(), 1);
    let login = sent[0].strip_prefix("Authorization: Basic ").unwrap();
    // 4 characters for each 3 bytes of `user:` and 2047 bytes typed.
    assert_eq!(login.len(), (300 + 1 + 2047usize).div_ceil(3) * 4);

    // 102397 bytes of user, `:` and one of password: 102399 fit.
    let user = "u".repeat(102_397);
    let s = Server::new(CLOSED);
    let run = curl_typing(&["-u", &user, &s.url()], b"x\n");
    assert_eq!((run.code, run.stderr.len()), (0, 256));
    assert_eq!(logins(&s.request()).len(), 1);
    // 102400 do not, and nothing is transferred: no server listens.
    let run = curl_typing(&["-u", &user, "http://127.0.0.1:1/"], b"xy\n");
    assert_eq!((run.code, run.stderr.len()), (27, 256));
}

/// `--remove-on-error`: the file a failed transfer wrote is removed, a
/// note saying so when tracing; one that is no regular file is kept,
/// warned of; one never opened, as the transfer failed first, is kept as
/// it was; and a transfer that succeeds keeps its file.
#[test]
fn removes_the_file_a_failed_transfer_wrote() {
    const PARTIAL: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nhalf";
    let dir = std::env::temp_dir().join(format!("curl-tool-rm-on-error-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("out");
    let name = file.to_str().unwrap();
    let s = Server::new(PARTIAL);
    let run = curl(&[
        "--no-progress-meter",
        "-v",
        "--remove-on-error",
        &s.url(),
        "-o",
        name,
    ]);
    let said: Vec<_> = run
        .stderr
        .lines()
        .filter(|l| !l.starts_with(['*', '<', '>', '{', '}']))
        .collect();
    assert_eq!(run.code, 18);
    let note = format!("Note: Removed output file: {name}");
    assert_eq!(
        said,
        [
            "curl: (18) end of response with 16 bytes missing",
            note.as_str()
        ]
    );
    assert!(!file.exists());
    // Not tracing, nothing is said of it.
    let s = Server::new(PARTIAL);
    let run = curl(&["-sS", "--remove-on-error", &s.url(), "-o", name]);
    assert_eq!(
        run.stderr,
        "curl: (18) end of response with 16 bytes missing\n"
    );
    assert!(!file.exists());
    let s = Server::new(PARTIAL);
    let run = curl(&[
        "-S",
        "--no-progress-meter",
        "--remove-on-error",
        &s.url(),
        "-o",
        "/dev/null",
    ]);
    assert_eq!(
        run.stderr,
        "curl: (18) end of response with 16 bytes missing\n\
         Warning: Skipping removal; not a regular file: /dev/null\n"
    );
    std::fs::write(&file, "before").unwrap();
    let run = curl(&[
        "-sS",
        "--remove-on-error",
        "http://127.0.0.1:1/",
        "-o",
        name,
    ]);
    assert_eq!(run.code, 7);
    assert_eq!(std::fs::read(&file).unwrap(), b"before");
    let s = Server::new(OK);
    let run = curl(&["-sS", "--remove-on-error", &s.url(), "-o", name]);
    assert_eq!(
        (run.code, std::fs::read(&file).unwrap()),
        (0, b"-foo-\n".to_vec())
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
