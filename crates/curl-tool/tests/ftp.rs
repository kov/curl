//! The tool's FTP options: what each sets, as `--libcurl` says it, and
//! the commands a server is sent for them.
//!
//! The expectations are the C tool's: `CURL_TOOL_UNDER_TEST` names
//! another tool to run them on, as
//! `CURL_TOOL_UNDER_TEST=build/c/src/curl LD_LIBRARY_PATH=build/c/lib`.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::thread::JoinHandle;

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Run the tool with `args`, without a configuration file.
fn curl(args: &[&str]) -> Run {
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let out = Command::new(tool)
        .arg("-q")
        .args(args)
        .env_remove("CURL_CA_BUNDLE")
        .env_remove("SSL_CERT_DIR")
        .env_remove("SSL_CERT_FILE")
        .output()
        .unwrap();
    Run {
        code: out.status.code().unwrap(),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

/// The `curl_easy_setopt` lines `--libcurl` writes for a download of
/// `ftp://127.0.0.1:1/a/f` with `args`, the URL's own and the ones every
/// transfer has left out: nothing listens there, so it fails as it
/// connects, the options all set.
fn ftp_setopts(args: &[&str]) -> Vec<String> {
    let r = curl(
        &[
            &["-s", "--libcurl", "-", "-o", "/dev/null"],
            args,
            &["ftp://127.0.0.1:1/a/f"],
        ]
        .concat(),
    );
    assert_eq!(r.code, 7, "{args:?}: {}", r.stderr);
    let common = [
        "CURLOPT_URL,",
        "CURLOPT_BUFFERSIZE,",
        "CURLOPT_NOPROGRESS,",
        "CURLOPT_USERAGENT,",
        "CURLOPT_MAXREDIRS,",
        "CURLOPT_HTTP_VERSION,",
        "CURLOPT_SSH_KNOWNHOSTS,",
        "CURLOPT_SSLVERSION,",
        "CURLOPT_TCP_KEEPALIVE,",
        "CURLOPT_WRITEDATA,",
    ];
    r.stdout
        .lines()
        .filter_map(|l| l.trim().strip_prefix("curl_easy_setopt(curl, "))
        .filter(|l| !common.iter().any(|c| l.starts_with(c)))
        .map(str::to_owned)
        .collect()
}

/// Each FTP option as C's tool sets it (`ftp_setopts`), the zero ones
/// left out as its `--libcurl` leaves them; a later `--ftp-ssl-ccc`
/// keeps the mode an earlier `--ftp-ssl-ccc-mode` chose.
#[test]
fn sets_the_ftp_options_asked_for() {
    assert_eq!(ftp_setopts(&[]), ["CURLOPT_FTP_SKIP_PASV_IP, 1L);"]);
    assert_eq!(
        ftp_setopts(&[
            "-P",
            "-",
            "--ftp-ssl-ccc-mode",
            "active",
            "--ftp-ssl-ccc",
            "--ftp-method",
            "nocwd",
            "--ftp-account",
            "acc",
            "--ftp-alternative-to-user",
            "alt",
            "--ftp-pret",
            "--ftp-create-dirs",
            "--ftp-ssl-control",
        ]),
        [
            "CURLOPT_FTPPORT, \"-\");",
            "CURLOPT_FTP_SSL_CCC, (long)CURLFTPSSL_CCC_ACTIVE);",
            "CURLOPT_FTP_ACCOUNT, \"acc\");",
            "CURLOPT_FTP_SKIP_PASV_IP, 1L);",
            "CURLOPT_FTP_FILEMETHOD, 2L);",
            "CURLOPT_FTP_ALTERNATIVE_TO_USER, \"alt\");",
            "CURLOPT_FTP_USE_PRET, 1L);",
            "CURLOPT_USE_SSL, (long)CURLUSESSL_CONTROL);",
            "CURLOPT_FTP_CREATE_MISSING_DIRS, 2L);",
        ]
    );
    assert_eq!(
        ftp_setopts(&["--ftp-ssl-ccc", "--ftp-method", "singlecwd"]),
        [
            "CURLOPT_FTP_SSL_CCC, (long)CURLFTPSSL_CCC_PASSIVE);",
            "CURLOPT_FTP_SKIP_PASV_IP, 1L);",
            "CURLOPT_FTP_FILEMETHOD, 3L);",
        ]
    );
    assert_eq!(
        ftp_setopts(&[
            "--ftp-ssl-ccc-mode",
            "bogus",
            "--no-ftp-skip-pasv-ip",
            "--ftp-method",
            "multicwd"
        ]),
        [
            "CURLOPT_FTP_SSL_CCC, (long)CURLFTPSSL_CCC_PASSIVE);",
            "CURLOPT_FTP_FILEMETHOD, 1L);",
        ]
    );
}

/// `-Q` sends its command before the transfer, after it with a leading
/// `-` and just before it with a `+`, each list its own option.
#[test]
fn sorts_the_quote_commands() {
    let set = ftp_setopts(&["-Q", "NOOP", "-Q", "-SITE x", "-Q", "+PRE y"]);
    let lists: Vec<&String> = set.iter().filter(|l| l.contains("QUOTE")).collect();
    assert_eq!(
        lists,
        [
            "CURLOPT_QUOTE, slist1);",
            "CURLOPT_POSTQUOTE, slist2);",
            "CURLOPT_PREQUOTE, slist3);",
        ]
    );
    let r = curl(&[
        "-s",
        "--libcurl",
        "-",
        "-o",
        "/dev/null",
        "-Q",
        "NOOP",
        "-Q",
        "-SITE x",
        "-Q",
        "+PRE y",
        "ftp://127.0.0.1:1/f",
    ]);
    for (list, command) in [
        ("slist1", "\"NOOP\""),
        ("slist2", "\"SITE x\""),
        ("slist3", "\"PRE y\""),
    ] {
        let line = format!("{list} = curl_slist_append({list}, {command});");
        assert!(r.stdout.contains(&line), "{line}: {}", r.stdout);
    }
}

/// A server for one connection that logs the client in, answers `CWD`,
/// and closes once a data connection is asked for; joining it gives the
/// commands it was sent.
fn commands_server(pasv: &'static str) -> (u16, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut out = tcp.try_clone().unwrap();
        let mut read = BufReader::new(tcp);
        out.write_all(b"220 hi\r\n").unwrap();
        let mut got = Vec::new();
        loop {
            let mut line = String::new();
            if read.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let command = line.trim_end().to_owned();
            let verb = command.split(' ').next().unwrap_or("").to_owned();
            got.push(command);
            let answer: &str = match verb.as_str() {
                "USER" => "331 password?\r\n",
                "PASS" => "230 in\r\n",
                "PWD" => "257 \"/\" is it\r\n",
                "CWD" => "250 there\r\n",
                "PASV" if !pasv.is_empty() => pasv,
                _ => break,
            };
            out.write_all(answer.as_bytes()).unwrap();
        }
        got
    });
    (port, server)
}

/// The commands a download of `path` with `args` sends a
/// `commands_server`, the login left out, and what the tool said.
fn commands(path: &str, args: &[&str], pasv: &'static str) -> (Vec<String>, String) {
    let (port, server) = commands_server(pasv);
    let url = format!("ftp://127.0.0.1:{port}/{path}");
    let r = curl(&[&["-v", "-o", "/dev/null"], args, &[url.as_str()]].concat());
    let got = server.join().unwrap();
    let after: Vec<String> = got
        .into_iter()
        .filter(|c| !c.starts_with("USER ") && !c.starts_with("PASS ") && c != "PWD")
        .collect();
    (after, r.stderr)
}

/// The data connection is asked for passively by EPSV, or by PASV with
/// `--disable-epsv` until `--epsv` takes it back; actively by EPRT, or by
/// PORT with `--disable-eprt` until `--eprt` does.
#[test]
fn asks_for_the_data_connection_as_told() {
    let first = |args: &[&str]| commands("f", args, "").0.into_iter().next().unwrap();
    assert!(first(&[]).starts_with("EPSV"));
    assert!(first(&["--disable-epsv"]).starts_with("PASV"));
    assert!(first(&["--disable-epsv", "--epsv"]).starts_with("EPSV"));
    assert!(first(&["-P", "127.0.0.1"]).starts_with("EPRT |1|127.0.0.1|"));
    assert!(first(&["-P", "127.0.0.1", "--disable-eprt"]).starts_with("PORT 127,0,0,1,"));
    assert!(first(&["-P", "127.0.0.1", "--disable-eprt", "--eprt"]).starts_with("EPRT"));
}

/// Each `--ftp-method` reaches the file's directory its way: a CWD for
/// each part, one for the whole, or none.
#[test]
fn reaches_the_directory_as_told() {
    let cwds = |args: &[&str]| {
        commands("a/b/f", args, "")
            .0
            .into_iter()
            .filter(|c| c.starts_with("CWD"))
            .collect::<Vec<_>>()
    };
    assert_eq!(cwds(&[]), ["CWD a", "CWD b"]);
    assert_eq!(cwds(&["--ftp-method", "multicwd"]), ["CWD a", "CWD b"]);
    assert_eq!(cwds(&["--ftp-method", "singlecwd"]), ["CWD a/b"]);
    assert!(cwds(&["--ftp-method", "nocwd"]).is_empty());
}

/// The address a PASV answer names is passed over for the control
/// connection's, unless `--no-ftp-skip-pasv-ip` says to use it.
#[test]
fn skips_the_pasv_address_unless_told() {
    const PASV: &str = "227 Entering Passive Mode (127,0,0,2,0,1)\r\n";
    let (_, said) = commands("f", &["--disable-epsv"], PASV);
    assert!(
        said.contains("Skip 127.0.0.2 for data connection, reuse 127.0.0.1 instead"),
        "{said}"
    );
    // macOS's loopback has 127.0.0.1 alone: a connect to 127.0.0.2 goes
    // unanswered there, where Linux's is refused at once.
    let (_, said) = commands(
        "f",
        &[
            "--disable-epsv",
            "--no-ftp-skip-pasv-ip",
            "--connect-timeout",
            "1",
        ],
        PASV,
    );
    assert!(!said.contains("Skip 127.0.0.2"), "{said}");
    assert!(said.contains("Connecting to 127.0.0.2"), "{said}");
}

/// `--ssl` turns `--ftp-ssl-control` off, and the other way round, each
/// saying so; either alone says only what it is.
#[test]
fn says_which_tls_option_overrides_which() {
    let said = |args: &[&str]| {
        let quiet = ["--no-progress-meter", "-o", "/dev/null"];
        curl(&[&quiet[..], args, &["ftp://127.0.0.1:1/f"]].concat()).stderr
    };
    let alone = said(&["--ssl"]);
    assert!(!alone.contains("overrides"), "{alone}");
    assert!(alone.contains("--ssl is an insecure option"), "{alone}");
    let control = said(&["--ftp-ssl-control"]);
    assert!(!control.contains("overrides"), "{control}");
    let late = said(&["--ftp-ssl-control", "--ssl"]);
    assert!(late.contains("--ssl overrides --ftp-ssl-control"), "{late}");
    let early = said(&["--ssl", "--ftp-ssl-control"]);
    assert!(
        early.contains("--ftp-ssl-control overrides --ssl"),
        "{early}"
    );
}

/// The command that stored an upload, and the bytes stored.
type Stored = Option<(String, Vec<u8>)>;

/// A server for one connection that takes an upload by EPSV, and gives
/// what it stored, if it got that far.
fn upload_server() -> (u16, JoinHandle<Stored>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut out = tcp.try_clone().unwrap();
        let mut read = BufReader::new(tcp);
        out.write_all(b"220 hi\r\n").unwrap();
        let mut data = None;
        let mut stored = None;
        loop {
            let mut line = String::new();
            if read.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let command = line.trim_end().to_owned();
            let answer = match command.split(' ').next().unwrap_or("") {
                "USER" => "331 password?\r\n".to_owned(),
                "PASS" => "230 in\r\n".to_owned(),
                "PWD" => "257 \"/\" is it\r\n".to_owned(),
                "TYPE" => "200 binary\r\n".to_owned(),
                "EPSV" => {
                    let l = TcpListener::bind("127.0.0.1:0").unwrap();
                    let p = l.local_addr().unwrap().port();
                    data = Some(l);
                    format!("229 there (|||{p}|)\r\n")
                }
                "STOR" | "APPE" => {
                    out.write_all(b"150 go\r\n").unwrap();
                    let (mut d, _) = data.take().unwrap().accept().unwrap();
                    let mut got = Vec::new();
                    std::io::Read::read_to_end(&mut d, &mut got).unwrap();
                    stored = Some((command, got));
                    "226 stored\r\n".to_owned()
                }
                "QUIT" => {
                    out.write_all(b"221 bye\r\n").unwrap();
                    break;
                }
                _ => "500 what\r\n".to_owned(),
            };
            out.write_all(answer.as_bytes()).unwrap();
        }
        stored
    });
    (port, server)
}

/// `-T -` resumed seeks standard input when it is a file, and reads up to
/// the point when it is a pipe (`tool_seek_cb`): past its end, the file
/// is appended nothing, and the pipe fails to read.
#[test]
fn a_resumed_upload_seeks_standard_input_if_it_can() {
    let body = b"ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNO";
    let dir = std::env::temp_dir().join(format!("curl-tool-seek-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("up");
    std::fs::write(&path, body).unwrap();
    let run = |from: &str, piped: bool| {
        let (port, server) = upload_server();
        let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
            .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
        let stdin = if piped {
            std::process::Stdio::piped()
        } else {
            std::fs::File::open(&path).unwrap().into()
        };
        let mut child = Command::new(tool)
            .args(["-q", "-sS", "-T", "-", "-C", from])
            .arg(format!("ftp://127.0.0.1:{port}/f"))
            .stdin(stdin)
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        if piped {
            child.stdin.take().unwrap().write_all(body).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        let stderr = String::from_utf8(out.stderr).unwrap();
        (out.status.code().unwrap(), stderr, server.join().unwrap())
    };
    let rest = Some(("APPE f".to_owned(), body[20..].to_vec()));
    assert_eq!(run("20", false), (0, String::new(), rest.clone()));
    assert_eq!(run("20", true), (0, String::new(), rest));
    let nothing = Some(("APPE f".to_owned(), Vec::new()));
    assert_eq!(run("50", false), (0, String::new(), nothing));
    let short = "curl: (31) Failed to read data\n".to_owned();
    assert_eq!(run("50", true), (31, short, None));
    std::fs::remove_dir_all(&dir).unwrap();
}
