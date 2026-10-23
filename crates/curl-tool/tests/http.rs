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
    curl_columns(args, None)
}

/// `curl`, with messages wrapped at `columns` instead of the default 79:
/// a message naming a file under the temporary directory is as long as
/// that directory's name.
fn curl_columns(args: &[&str], columns: Option<&str>) -> Run {
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let mut command = Command::new(tool);
    if let Some(columns) = columns {
        command.env("COLUMNS", columns);
    }
    let out = command.arg("-q").args(args).output().unwrap();
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
    let run = curl_columns(&["-s", "-D", file.to_str().unwrap(), &s.url()], Some("500"));
    assert_eq!((run.code, &run.stdout[..]), (0, &b"-foo-\n"[..]));
    assert_eq!(
        std::fs::read(&file).unwrap(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nA: b\r\n\r\n"
    );
    std::fs::remove_dir_all(&dir).unwrap();
    // One that cannot be opened fails the transfer before it starts.
    let missing = dir.join("no/such/heads");
    let run = curl_columns(
        &[
            "-sS",
            "-D",
            missing.to_str().unwrap(),
            "http://127.0.0.1:1/",
        ],
        Some("500"),
    );
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

/// `-G` puts the data in the URL's query, after a `&` if it has one, and
/// asks with a GET, or a HEAD after `-I`; no body is sent.
#[test]
fn gets_the_data_in_the_query() {
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let url = format!("{}?x=1", s.url());
    let run = curl(&["-sS", "-G", "-d", "a=b", "--data-urlencode", "c=d e", &url]);
    assert_eq!((run.code, &run.stderr[..]), (0, ""));
    let request = s.request();
    assert!(
        request.starts_with("GET /?x=1&a=b&c=d+e HTTP/1.1\r\n"),
        "{request}"
    );
    assert!(request.ends_with("Accept: */*\r\n\r\n"), "{request}");
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let run = curl(&["-sS", "-I", "-G", "-d", "a", &s.url()]);
    assert_eq!((run.code, &run.stderr[..]), (0, ""));
    let request = s.request();
    assert!(request.starts_with("HEAD /?a HTTP/1.1\r\n"), "{request}");
    let run = curl(&["-G", "-d", "x", "-T", "/dev/null", "http://127.0.0.1:1/"]);
    assert_eq!(run.code, 2);
    assert_eq!(
        run.stderr,
        "Warning: You can only select one HTTP request method! You asked for both PUT \n\
         Warning: (-T, --upload-file) and GET (-G, --get).\n"
    );
    // A URL the query cannot be added to is said once, in the tool's
    // words.
    let run = curl(&["-sS", "-G", "-d", "a", "nosuch://host/"]);
    assert_eq!(run.code, 1);
    assert_eq!(
        run.stderr,
        "curl: (1) Could not parse the URL, failed to set query\n"
    );
}

/// `--url-query` adds to the query, encoded unless it starts with `+`,
/// whatever the method; `-G` with data puts the data there instead.
#[test]
fn adds_the_url_query() {
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let run = curl(&[
        "-sS",
        "--url-query",
        "a b",
        "--url-query",
        "+%3d",
        "-d",
        "x",
        &s.url(),
    ]);
    assert_eq!((run.code, &run.stderr[..]), (0, ""));
    let request = s.request();
    assert!(
        request.starts_with("POST /?a+b&%3D HTTP/1.1\r\n"),
        "{request}"
    );
    assert!(request.ends_with("\r\n\r\nx"), "{request}");
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let run = curl(&["-sS", "--url-query", "q", "-G", "-d", "x", &s.url()]);
    assert_eq!((run.code, &run.stderr[..]), (0, ""));
    let request = s.request();
    assert!(request.starts_with("GET /?x HTTP/1.1\r\n"), "{request}");
    // Joined, they must fit in C's buffer of 100000 bytes, its
    // terminating zero counted.
    let half = format!("+{}", "a".repeat(49_999));
    let more = format!("+{}", "a".repeat(50_000));
    let run = curl(&[
        "-s",
        "--url-query",
        &half,
        "--url-query",
        &half,
        "http://127.0.0.1:1/",
    ]);
    assert_eq!(run.code, 7);
    let run = curl(&[
        "--url-query",
        &more,
        "--url-query",
        &half,
        "http://127.0.0.1:1/",
    ]);
    assert_eq!(run.code, 2);
    assert!(
        run.stderr
            .starts_with("curl: option --url-query: out of memory\n"),
        "{}",
        run.stderr
    );
}

/// `--request-target` replaces the request line's target, also to a
/// proxy, and may not be blank.
#[test]
fn sends_the_request_target() {
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let proxy = s.url();
    let run = curl(&[
        "-sS",
        "--request-target",
        "*",
        "-X",
        "OPTIONS",
        "-x",
        &proxy,
        "http://example.invalid/p?q",
    ]);
    assert_eq!((run.code, &run.stderr[..]), (0, ""));
    let request = s.request();
    assert!(
        request.starts_with("OPTIONS * HTTP/1.1\r\nHost: example.invalid\r\n"),
        "{request}"
    );
    let run = curl(&["--request-target", "", "http://127.0.0.1:1/"]);
    assert_eq!(run.code, 2);
    assert!(
        run.stderr.starts_with(
            "curl: option --request-target: blank argument where content is expected\n"
        ),
        "{}",
        run.stderr
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

/// `--xattr` stores where a download came from with the file the
/// transfer wrote, once it succeeded: a pipe takes no attributes, and
/// that is warned of, with the reason.
#[test]
fn stores_where_a_download_came_from() {
    let dir = scratch("xattr");
    let pipe = dir.join("pipe");
    let made = Command::new("mkfifo").arg(&pipe).status().unwrap();
    assert!(made.success());
    let name = pipe.to_str().unwrap();
    for (reply, args, warned) in [
        (OK, &["--xattr"][..], true),
        (
            &b"HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\n\r\nabcde"[..],
            &["--xattr", "--fail-with-body"][..],
            false,
        ),
    ] {
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let pipe = pipe.clone();
            let done = done.clone();
            std::thread::spawn(move || read_fifo(&pipe, &done))
        };
        let s = Server::new(reply);
        let url = s.url();
        let mut all = vec!["--no-progress-meter", "-o", name, &url];
        all.extend_from_slice(args);
        let run = curl_columns(&all, Some("1000"));
        done.store(true, std::sync::atomic::Ordering::SeqCst);
        let wrote = reader.join().unwrap();
        assert_eq!(
            wrote.len(),
            if warned { 6 } else { 5 },
            "{args:?}: exit {}, {}",
            run.code,
            run.stderr
        );
        let warning = format!(
            "Warning: Error setting extended attributes on '{name}': Operation not permitted\n"
        );
        assert_eq!(run.stderr.contains(&warning), warned, "{}", run.stderr);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Everything written to the fifo `path`, read without ever blocking on
/// a writer: the read end opens non-blocking and is polled, so a tool
/// that never opens its output leaves the reader to end with nothing
/// once `done` is set, not stuck in `open`. The end is the writer
/// closing after it wrote, or `done` with nothing more to read.
fn read_fifo(path: &std::path::Path, done: &std::sync::atomic::AtomicBool) -> Vec<u8> {
    use std::os::unix::fs::OpenOptionsExt as _;
    /// `O_NONBLOCK` on Linux.
    const O_NONBLOCK: i32 = 0o4000;
    let mut fifo = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(path)
        .unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match fifo.read(&mut buf) {
            // No writer yet reads as end of file too: only data seen
            // first makes it the end.
            Ok(0) if !got.is_empty() || done.load(std::sync::atomic::Ordering::SeqCst) => {
                return got;
            }
            Ok(0) => std::thread::sleep(std::time::Duration::from_millis(5)),
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if done.load(std::sync::atomic::Ordering::SeqCst) {
                    return got;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(e) => panic!("reading the fifo: {e}"),
        }
    }
}

/// HTTP's options are for a URL the tool takes for HTTP's: a file read
/// with `-c` and `-b` keeps no jar, sends nothing and warns of nothing,
/// as C's `http_setopts` is not run for it.
#[test]
fn gives_http_s_options_only_to_http() {
    let dir = scratch("not-http");
    let jar = dir.join("jar");
    let file = dir.join("f");
    std::fs::write(&file, b"x").unwrap();
    let url = format!("file://{}", file.to_str().unwrap());
    let long = format!("a={}", "b".repeat(8200));
    let run = curl(&["-sS", "-c", jar.to_str().unwrap(), "-b", &long, &url]);
    assert_eq!(
        (run.code, &run.stdout[..], &run.stderr[..]),
        (0, &b"x"[..], "")
    );
    assert!(!jar.exists(), "no jar for a file");
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let run = curl(&["-sS", "-c", jar.to_str().unwrap(), &s.url()]);
    assert_eq!((run.code, &run.stderr[..]), (0, ""));
    assert!(jar.exists(), "a jar for HTTP");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// An `ipfs://` URL goes to the gateway, under its path, as `/ipfs/` and
/// the URL's host and path, without HTTP's options; a gateway that does
/// not parse fails it, said once.
#[test]
fn goes_to_the_ipfs_gateway() {
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let gateway = format!("{}g", s.url());
    let run = curl(&[
        "-sS",
        "-b",
        "a=b",
        "--ipfs-gateway",
        &gateway,
        "ipfs://cid/p?q#f",
    ]);
    assert_eq!((run.code, &run.stderr[..]), (0, ""));
    let request = s.request();
    assert!(
        request.starts_with("GET /g/ipfs/cid/p?q HTTP/1.1\r\n"),
        "{request}"
    );
    assert!(!request.contains("Cookie"), "{request}");
    let run = curl(&["--ipfs-gateway", "http://a,b:1", "ipfs://cid"]);
    assert_eq!(run.code, 43);
    assert!(
        run.stderr
            .starts_with("curl: --ipfs-gateway was given a malformed URL\ncurl: try "),
        "{}",
        run.stderr
    );
    assert_eq!(run.stderr.lines().count(), 2, "{}", run.stderr);
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
    // One write, so one read takes all of it. A tool that asks for
    // nothing may exit before the write, which is then a broken pipe,
    // not a failure of the test.
    match child.stdin.take().unwrap().write_all(typed) {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => panic!("typing: {e}"),
        _ => {}
    }
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
    let run = curl_columns(
        &[
            "--no-progress-meter",
            "-v",
            "--remove-on-error",
            &s.url(),
            "-o",
            name,
        ],
        Some("500"),
    );
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
    let run = curl_columns(
        &["-sS", "--remove-on-error", &s.url(), "-o", name],
        Some("500"),
    );
    assert_eq!(
        run.stderr,
        "curl: (18) end of response with 16 bytes missing\n"
    );
    assert!(!file.exists());
    let s = Server::new(PARTIAL);
    let run = curl_columns(
        &[
            "-S",
            "--no-progress-meter",
            "--remove-on-error",
            &s.url(),
            "-o",
            "/dev/null",
        ],
        Some("500"),
    );
    assert_eq!(
        run.stderr,
        "curl: (18) end of response with 16 bytes missing\n\
         Warning: Skipping removal; not a regular file: /dev/null\n"
    );
    std::fs::write(&file, "before").unwrap();
    let run = curl_columns(
        &[
            "-sS",
            "--remove-on-error",
            "http://127.0.0.1:1/",
            "-o",
            name,
        ],
        Some("500"),
    );
    assert_eq!(run.code, 7);
    assert_eq!(std::fs::read(&file).unwrap(), b"before");
    let s = Server::new(OK);
    let run = curl_columns(
        &["-sS", "--remove-on-error", &s.url(), "-o", name],
        Some("500"),
    );
    assert_eq!(
        (run.code, std::fs::read(&file).unwrap()),
        (0, b"-foo-\n".to_vec())
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `request` with each boundary it names written `B0`, `B1`, ... in the
/// order they come: they are random.
fn unbound(request: &str) -> String {
    let mut out = request.to_owned();
    let mut rest = request;
    let mut n = 0;
    while let Some(at) = rest.find("boundary=") {
        rest = &rest[at + "boundary=".len()..];
        let end = rest.find("\r\n").unwrap();
        out = out.replace(&rest[..end], &format!("B{n}"));
        n += 1;
    }
    out
}

/// `-F` warns of what it passes over as C's tool does: data after a
/// quoted value that is not blank, an unknown setting, a setting a kind
/// of part does not take, and what is left after a value; and sends the
/// rest.
#[test]
fn warns_of_form_fields_as_c_does() {
    let dir = scratch("form-warns");
    let file = dir.join("f1.txt");
    std::fs::write(&file, "F1").unwrap();
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let e = format!("e=<{};filename=z;encoder=8bit", file.display());
    let run = curl_columns(
        &[
            "--no-progress-meter",
            "-F",
            r#"a="x" y;type=t"#,
            "-F",
            r#"b="x" ;type=t"#,
            "-F",
            "c=v;bogus=1",
            "-F",
            "d=(;filename=x;encoder=y;type=multipart/mixed",
            "-F",
            &e,
            "-F",
            "=)",
            "-F",
            "f=v;type=t x",
            &s.url(),
        ],
        Some("500"),
    );
    assert_eq!(
        (run.code, &run.stderr[..]),
        (
            0,
            "Warning: Trailing data after quoted form parameter\n\
             Warning: skip unknown form field: bogus=1\n\
             Warning: Field filename not allowed here: x\n\
             Warning: Field encoder not allowed here: y\n\
             Warning: Field filename not allowed here: z\n\
             Warning: garbage at end of field specification:  x\n"
        )
    );
    let request = unbound(&s.request());
    let body = "--B0\r\n\
        Content-Disposition: form-data; name=\"a\"\r\nContent-Type: t\r\n\r\nx\r\n--B0\r\n\
        Content-Disposition: form-data; name=\"b\"\r\nContent-Type: t\r\n\r\nx\r\n--B0\r\n\
        Content-Disposition: form-data; name=\"c\"\r\n\r\nv\r\n--B0\r\n\
        Content-Disposition: form-data; name=\"d\"\r\n\
        Content-Type: multipart/mixed; boundary=B1\r\n\r\n--B1\r\n\
        Content-Disposition: attachment; name=\"e\"\r\n\
        Content-Transfer-Encoding: 8bit\r\n\r\nF1\r\n--B1--\r\n\r\n--B0\r\n\
        Content-Disposition: form-data; name=\"f\"\r\nContent-Type: t\r\n\r\nv\r\n--B0--\r\n";
    assert!(
        request.ends_with(&format!(
            "Content-Length: 859\r\n\
             Content-Type: multipart/form-data; boundary=B0\r\n\r\n{body}"
        )),
        "{request}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Standard input that is a regular file is a part read as it is sent:
/// from where it stood, as many bytes as it then held, again from there
/// when a redirect sends the part again, though the file has grown.
#[test]
fn sends_standard_input_again_as_it_stood() {
    let dir = scratch("form-stdin");
    let file = dir.join("in");
    std::fs::write(&file, "0123456789").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let grown = file.clone();
    let server = std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        let mut requests = Vec::new();
        for reply in [
            &b"HTTP/1.1 307 Again\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n"[..],
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        ] {
            let mut got = Vec::new();
            let mut buf = [0; 4096];
            while !request_ended(&got) {
                match peer.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            requests.push(String::from_utf8(got).unwrap());
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&grown)
                .unwrap();
            f.write_all(b"XYZ").unwrap();
            peer.write_all(reply).unwrap();
        }
        requests
    });
    let mut input = std::fs::File::open(&file).unwrap();
    std::io::Seek::seek(&mut input, std::io::SeekFrom::Start(3)).unwrap();
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let out = Command::new(tool)
        .args(["-q", "-sS", "-L", "-F", "a=@-"])
        .arg(format!("http://127.0.0.1:{port}/"))
        .stdin(input)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let requests = server.join().unwrap();
    for request in &requests {
        let request = unbound(request);
        assert!(
            request.ends_with(
                "\r\n\r\n--B0\r\n\
                 Content-Disposition: form-data; name=\"a\"; filename=\"-\"\r\n\r\n\
                 3456789\r\n--B0--\r\n"
            ),
            "{request}"
        );
    }
    assert_eq!(requests.len(), 2);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Standard input that cannot be read, a directory here, is read again
/// as the part is sent, and that read failing is said and ends the
/// transfer.
#[test]
fn fails_on_standard_input_it_cannot_read() {
    let s = Server::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let dir = std::fs::File::open(std::env::temp_dir()).unwrap();
    let out = Command::new(tool)
        .args([
            "-q",
            "--no-progress-meter",
            "-H",
            "Expect:",
            "-F",
            "a=<-",
            &s.url(),
        ])
        .stdin(dir)
        .output()
        .unwrap();
    assert_eq!(
        (out.status.code(), &String::from_utf8_lossy(&out.stderr)[..]),
        (
            Some(42),
            "Warning: Failed to read from stdin: Is a directory\n\
             curl: (42) operation aborted by callback\n"
        )
    );
    let request = unbound(&s.request());
    assert!(
        request.ends_with("--B0\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n\r\n"),
        "{request}"
    );
}

/// The tool with `args` and only the environment `env` names for the
/// IPFS gateway, `HOME` among them.
fn curl_ipfs_env(args: &[&str], env: &[(&str, &std::ffi::OsStr)]) -> Run {
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let mut command = Command::new(tool);
    command
        .env_remove("IPFS_GATEWAY")
        .env_remove("IPFS_PATH")
        .env_remove("HOME");
    for (name, value) in env {
        command.env(name, value);
    }
    let out = command.arg("-q").args(args).output().unwrap();
    Run {
        code: out.status.code().unwrap(),
        stdout: out.stdout,
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

/// Without `--ipfs-gateway`, the gateway is `IPFS_GATEWAY`, else the
/// first line of `gateway` in `IPFS_PATH`, a `/` put between them, else
/// in `~/.ipfs`, an empty `IPFS_PATH` being none; a `gateway` that
/// cannot be read is no gateway.
#[test]
fn finds_the_ipfs_gateway_as_c_does() {
    let dir = scratch("ipfs-env");
    let home = dir.join("home");
    std::fs::create_dir_all(home.join(".ipfs")).unwrap();
    let path = dir.join("path");
    std::fs::create_dir_all(&path).unwrap();
    let unreadable = dir.join("unreadable");
    std::fs::create_dir_all(unreadable.join("gateway")).unwrap();
    let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    for at in ["gateway", "home", "path"] {
        let s = Server::new(ok);
        let url = s.url();
        std::fs::write(home.join(".ipfs/gateway"), format!("{url}\nnot this\n")).unwrap();
        std::fs::write(path.join("gateway"), format!("{url}\r\n")).unwrap();
        let empty = std::ffi::OsStr::new("");
        let env: &[(&str, &std::ffi::OsStr)] = match at {
            "gateway" => &[("IPFS_GATEWAY", url.as_ref())],
            "home" => &[("IPFS_PATH", empty), ("HOME", home.as_os_str())],
            _ => &[("IPFS_PATH", path.as_os_str()), ("HOME", empty)],
        };
        let run = curl_ipfs_env(&["-sS", "ipfs://cid/p"], env);
        assert_eq!((run.code, &run.stderr[..]), (0, ""), "{at}");
        let request = s.request();
        assert!(
            request.starts_with("GET /ipfs/cid/p HTTP/1.1\r\n"),
            "{at}: {request}"
        );
    }
    let run = curl_ipfs_env(
        &["-sS", "ipfs://cid"],
        &[("IPFS_PATH", unreadable.as_os_str())],
    );
    assert_eq!(run.code, 37);
    assert!(
        run.stderr
            .starts_with("curl: IPFS automatic gateway detection failed\n"),
        "{}",
        run.stderr
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The debug build's times and sizes for `--write-out`, as tests 970
/// and 1981 set them: `CURL_TIME` for the time now and every time, both
/// speeds and the local port, `CURL_DEBUG_SIZE` for the header and
/// request sizes; a status code, three digits as text and a number in
/// JSON; a value missing, nothing as text and `null` in JSON; and a
/// part of the URL and an address, as they are in text and quoted in
/// JSON.
#[cfg(feature = "debug-hooks")]
#[test]
fn writes_out_the_debug_build_s_times_and_sizes() {
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let run = |env: &[(&str, &str)], format: &str| {
        let s = Server::new(OK);
        let out = Command::new(&tool)
            .args(["-q", "-s", "-o", "/dev/null", "-w", format, &s.url()])
            .envs(env.iter().copied())
            .output()
            .unwrap();
        s.request();
        assert_eq!(out.status.code(), Some(0), "{format}");
        String::from_utf8(out.stdout).unwrap()
    };
    assert_eq!(
        run(
            &[("CURL_TIME", "1754037103"), ("LC_TIME", "C"), ("TZ", "UTC")],
            "Time: %time{%d/%b/%Y %H:%M:%S.%f %z %Z%%s %s}\n"
        ),
        "Time: 01/Aug/2025 08:31:43.037103 +0000 UTC%s 1754037103\n"
    );
    assert_eq!(
        run(
            &[("CURL_TIME", "13"), ("CURL_DEBUG_SIZE", "4019")],
            "%{time_total} %{size_header} %{size_request} %{local_port} %{speed_download}"
        ),
        "0.000013 4019 4019 13 13"
    );
    let json = run(
        &[],
        "%{http_connect} [%{redirect_url}] [%{url.path}] [%{local_ip}] %{json}",
    );
    assert!(json.starts_with("000 [] [/] [127.0.0.1] {"), "{json}");
    assert!(json.contains(",\"local_ip\":\"127.0.0.1\","), "{json}");
    assert!(json.contains(",\"url.path\":\"/\","), "{json}");
    assert!(json.contains(",\"http_connect\":0,"), "{json}");
    assert!(json.contains(",\"redirect_url\":null,"), "{json}");
}

/// `--httpsig-*` signs the request with the algorithm named in any
/// case, Ed25519 unless named, its key read from the file after `@`, a
/// file named `-` among them; an unknown algorithm and an empty key file
/// are refused as C refuses them. Ed25519 needs a TLS backend: without
/// one it is refused by its name.
#[test]
fn signs_the_request_as_told() {
    let keys = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data");
    let ed25519 = keys.join("data-httpsig-ed25519.key");
    let hmac = keys.join("data-httpsig-hmac-sha256.key");
    let dir = scratch("httpsig");
    std::fs::copy(&hmac, dir.join("-")).unwrap();
    std::fs::write(dir.join("empty"), "").unwrap();
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let run = |args: &[&str], url: &str| {
        let out = Command::new(&tool)
            .arg("-q")
            .args(["-sS", "--httpsig-keyid", "k"])
            .args(args)
            .arg(url)
            .current_dir(&dir)
            .output()
            .unwrap();
        (
            out.status.code().unwrap(),
            String::from_utf8(out.stderr).unwrap(),
        )
    };
    let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let key = |p: &std::path::Path| format!("@{}", p.display());
    let no_tls = "curl: (4) httpsig: algorithm 'ed25519' not supported by TLS backend\n";
    for (args, alg) in [
        (
            vec![
                "--httpsig-algo",
                "HMAC-SHA256",
                "--httpsig-key",
                &key(&hmac),
            ],
            "hmac-sha256",
        ),
        (
            vec!["--httpsig-algo", "hmac-sha256", "--httpsig-key", "@-"],
            "hmac-sha256",
        ),
        (
            vec!["--httpsig-algo", "Ed25519", "--httpsig-key", &key(&ed25519)],
            "ed25519",
        ),
        (vec!["--httpsig-key", &key(&ed25519)], "ed25519"),
    ] {
        let s = Server::new(ok);
        let got = run(&args, &s.url());
        let request = s.request();
        if alg == "ed25519" && got == (4, no_tls.to_owned()) {
            continue;
        }
        assert_eq!(got, (0, String::new()), "{args:?}");
        let input = format!(";keyid=\"k\";alg=\"{alg}\"\r\n");
        assert!(request.contains(&input), "{args:?}: {request}");
        assert!(
            request.contains("\r\nSignature: sig1=:"),
            "{args:?}: {request}"
        );
    }
    let (code, stderr) = run(
        &["--httpsig-algo", "rsa", "--httpsig-key", "00"],
        "http://127.0.0.1:1/",
    );
    assert_eq!(code, 2);
    assert!(
        stderr.starts_with("curl: --httpsig-algo: unsupported algorithm 'rsa'\n"),
        "{stderr}"
    );
    let (code, stderr) = run(&["--httpsig-key", "@empty"], "http://127.0.0.1:1/");
    assert_eq!(code, 43);
    assert!(
        stderr.starts_with("curl: httpsig: key file 'empty' is empty\n"),
        "{stderr}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `-x` alone sends the request to the proxy, with the `--proxy-header`
/// lines; `-p` alone tunnels through the proxy the environment names,
/// `--noproxy` alone goes around it and `--proxy-digest` alone is its
/// method; `-b` naming a file sends the cookies it holds.
#[test]
fn proxies_and_cookie_files_reach_the_request() {
    let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let s = Server::new(ok);
    let run = curl(&[
        "-sS",
        "-x",
        &s.url(),
        "--proxy-header",
        "X-P: 1",
        "http://example.test/a",
    ]);
    assert_eq!((run.code, &run.stderr[..]), (0, ""));
    let request = s.request();
    assert!(
        request.starts_with("GET http://example.test/a HTTP/1.1\r\nHost: example.test\r\n"),
        "{request}"
    );
    assert!(request.contains("\r\nX-P: 1\r\n"), "{request}");
    // The proxy the environment names: `-p` alone tunnels through it,
    // `--noproxy` alone goes around it.
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let s = Server::new(b"HTTP/1.1 200 Connection established\r\n\r\n");
    Command::new(&tool)
        .args(["-q", "-s", "-p", "http://example.test/x"])
        .env("http_proxy", s.url())
        .output()
        .unwrap();
    let request = s.request();
    assert!(
        request.starts_with("CONNECT example.test:80 HTTP/1.1\r\n"),
        "{request}"
    );
    let s = Server::new(ok);
    let out = Command::new(&tool)
        .args(["-q", "-sS", "--noproxy", "127.0.0.1", &s.url()])
        .env("http_proxy", "http://127.0.0.1:1/")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(s.request().starts_with("GET / HTTP/1.1\r\n"));
    // A proxy method alone is the environment's proxy's: Digest sends
    // nothing before it is asked, as Basic would.
    let s = Server::new(ok);
    let out = Command::new(&tool)
        .args(["-q", "-sS", "--proxy-digest", "--proxy-user", "u:p"])
        .arg("http://example.test/d")
        .env("http_proxy", s.url())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let request = s.request();
    assert!(
        request.starts_with("GET http://example.test/d HTTP/1.1\r\n"),
        "{request}"
    );
    assert!(!request.contains("Proxy-Authorization"), "{request}");
    let dir = scratch("cookie-file");
    let jar = dir.join("jar");
    std::fs::write(&jar, "127.0.0.1\tFALSE\t/\tFALSE\t0\tname\tvalue\n").unwrap();
    let s = Server::new(ok);
    let run = curl(&["-sS", "-b", jar.to_str().unwrap(), &s.url()]);
    assert_eq!((run.code, &run.stderr[..]), (0, ""));
    let request = s.request();
    assert!(request.contains("\r\nCookie: name=value\r\n"), "{request}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `-r` warns of a character in the range that is no digit, dash or
/// comma, and of nothing in one that has none.
#[test]
fn warns_of_odd_characters_in_a_range() {
    let warning = "Warning: Invalid character is found in given range.";
    for (range, warns) in [("1-2,3-4", false), ("1-a", true), ("x-2", true)] {
        // No transfer: the URL's port refuses.
        let run = curl_columns(
            &["--no-progress-meter", "-r", range, "http://127.0.0.1:1/"],
            Some("500"),
        );
        assert_eq!(
            run.stderr.starts_with(warning),
            warns,
            "{range}: {}",
            run.stderr
        );
        assert!(run.stderr.contains("curl: (7) "), "{range}: {}", run.stderr);
    }
}

/// The socket options a transfer sets through the tool's own handlers:
/// a priority the system refuses is warned of, and the transfer goes on
/// (`sockopt_callback`); `--mptcp` opens a Multipath TCP socket, which
/// talks to a plain TCP server as TCP (`tool_socket_open_mptcp_cb`).
#[test]
fn sets_the_socket_options_it_handles() {
    let s = Server::new(OK);
    let url = s.url();
    // Above 6 needs CAP_NET_ADMIN, which the tests do not run with.
    let run = curl(&["--no-progress-meter", "--vlan-priority", "7", &url]);
    assert_eq!((run.code, &run.stdout[..]), (0, &b"-foo-\n"[..]));
    let root = Command::new("id").arg("-u").output().unwrap().stdout == b"0\n";
    if !root {
        assert_eq!(
            run.stderr,
            "Warning: VLAN priority 7 failed with errno 1: Operation not permitted\n"
        );
    }
    s.request();
    let enabled = std::fs::read("/proc/sys/net/mptcp/enabled").is_ok_and(|e| e == b"1\n");
    if enabled {
        let s = Server::new(OK);
        let url = s.url();
        let run = curl(&["-s", "--mptcp", "--ip-tos", "CS1", &url]);
        assert_eq!((run.code, &run.stdout[..]), (0, &b"-foo-\n"[..]));
        assert!(s.request().starts_with("GET / HTTP/1.1\r\n"));
    }
}

/// One after another, the transfers share their connections, as C's
/// tool shares them through its share (`CURL_LOCK_DATA_CONNECT`): the
/// second reuses the first's.
#[test]
fn serial_transfers_share_a_connection() {
    let s = Server::script(vec![vec![OK.to_vec(), OK.to_vec()]]);
    let url = s.url();
    let run = curl(&[
        "-s",
        "-o",
        "/dev/null",
        "-o",
        "/dev/null",
        "-w",
        "%{num_connects}\n",
        &url,
        &url,
    ]);
    assert_eq!((run.code, &run.stdout[..]), (0, &b"1\n0\n"[..]));
    assert_eq!(s.request().matches("GET / ").count(), 2);
}

const COOKIE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nSet-Cookie: a=1\r\n\r\n";

/// In parallel the multi keeps the connections, and the share still
/// the cookies: a cookie the first transfer gets goes with the second,
/// over the connection it left.
#[test]
fn parallel_transfers_share_cookies_and_connections() {
    let s = Server::script(vec![vec![COOKIE.to_vec(), OK.to_vec()]]);
    let url = s.url();
    let run = curl(&[
        "-s",
        "-Z",
        "--parallel-max",
        "1",
        "-b",
        "nosuchfile",
        "-o",
        "/dev/null",
        "-o",
        "/dev/null",
        "-w",
        "%{num_connects}\n",
        &url,
        &url,
    ]);
    assert_eq!((run.code, &run.stdout[..]), (0, &b"1\n0\n"[..]));
    let requests = s.request();
    let second = requests.rsplit("GET / ").next().unwrap();
    assert!(second.contains("\r\nCookie: a=1\r\n"), "{requests}");
}
