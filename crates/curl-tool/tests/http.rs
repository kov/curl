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
    fn script(conns: Vec<Vec<Vec<u8>>>) -> Server {
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
