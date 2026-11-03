#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use super::*;
use crate::handler::DebugKind;
use crate::share::Told;

/// A session: a ticket, of TLS 1.3, of no date.
const PACKED: &[u8] = &[1, 4, 0, 1, b'T', 2, 3, 4, 3, 0, 0, 0, 0, 0, 0, 0, 0];

fn kept_by_a_share() -> (Easy, Share, Told) {
    let share = Share::new().unwrap();
    share.keep(Kind::SslSessions).unwrap();
    let told = Told::new(&share);
    let mut easy = Easy::new();
    easy.set_share(Some(share.clone())).unwrap();
    easy.share_watch = Some(told.handler());
    (easy, share, told)
}

fn no_notes() -> impl FnMut(DebugKind, &[u8]) {
    |_, _| {}
}

/// With neither a share keeping sessions nor a multi, a handle has no
/// cache: an import is refused, whatever it holds, and an export gives
/// nothing and is no error.
#[test]
fn a_handle_with_no_cache_has_no_sessions() {
    let mut easy = Easy::new();
    let share = Share::new().unwrap();
    share.keep(Kind::Cookies).unwrap();
    easy.set_share(Some(share)).unwrap();
    for packed in [PACKED, b"x"] {
        assert_eq!(
            easy.ssls_import(SessionFor::Key(b"k:G"), packed, &mut no_notes()),
            Err(ErrorKind::BadFunctionArgument)
        );
    }
    let done = easy
        .ssls_export()
        .deliver::<()>(&mut |_| panic!("no session to give"));
    assert_eq!(done.end(&easy, &mut no_notes()), Ok(()));
}

/// C's order of refusals: nothing to import or no peer named; then what
/// will not unpack, its salted HMAC not looked at; then a salted HMAC not
/// of its length. A key given makes the HMAC no matter.
#[test]
fn an_import_is_refused_in_c_s_order() {
    let (easy, ..) = kept_by_a_share();
    let bad = ErrorKind::BadFunctionArgument;
    let import = |who, packed: &[u8]| easy.ssls_import(who, packed, &mut no_notes());
    assert_eq!(import(SessionFor::Key(b"k:G"), &[]), Err(bad));
    assert_eq!(import(SessionFor::SaltedHmac(&[]), PACKED), Err(bad));
    assert_eq!(import(SessionFor::SaltedHmac(&[]), b"x"), Err(bad));
    let short = SessionFor::SaltedHmac(&[0; 5]);
    assert_eq!(import(short, b"x"), Err(ErrorKind::ReadError));
    assert_eq!(import(short, PACKED), Err(bad));
    assert_eq!(import(SessionFor::Key(b"k:G"), PACKED), Ok(()));
}

/// What will not unpack is refused with no lock taken; one that will is
/// kept under one use of the lock. An export holds it from before its
/// sessions are read until the last has gone out, as C holds it across its
/// function, with the library's own lock free meanwhile: the application's
/// function may use the share.
#[test]
fn the_application_is_told_as_c_calls_its_lock() {
    let (easy, share, told) = kept_by_a_share();
    let import = |packed: &[u8]| easy.ssls_import(SessionFor::Key(b"k:G"), packed, &mut no_notes());
    assert_eq!(import(b"x"), Err(ErrorKind::ReadError));
    assert_eq!(told.calls(), []);
    assert_eq!(import(PACKED), Ok(()));
    assert_eq!(told.uses(), [Kind::SslSessions]);

    let mut seen = Vec::new();
    let exporting = easy.ssls_export();
    assert_eq!(
        told.calls(),
        [(Some(Access::Single), Kind::SslSessions)],
        "locked before it was read"
    );
    let done = exporting.deliver::<()>(&mut |s| {
        seen.push((s.key.map(<[u8]>::to_vec), s.packed.to_vec()));
        assert!(share.sessions().is_some(), "the library's lock is free");
        assert_eq!(told.calls(), [], "not let go yet");
        Ok(())
    });
    assert_eq!(told.calls(), [(None, Kind::SslSessions)], "let go after");
    assert_eq!(done.end(&easy, &mut no_notes()), Ok(()));
    assert_eq!(seen, [(Some(b"k:G".to_vec()), PACKED.to_vec())]);
}

/// A share that stops keeping its sessions between a use's choice of it
/// and the use, as one racing a handle that links on another thread does,
/// leaves the use no cache: an import is refused as with none and an
/// export gives nothing, each lock told still let go, and the process goes
/// on. C uses the cache it has freed.
#[test]
fn sessions_gone_under_a_use_are_no_cache() {
    use crate::share::Emptying;
    let (mut easy, share, told) = kept_by_a_share();
    easy.share_watch = Some(Emptying::handler(&told, Kind::SslSessions));
    let import = easy.ssls_import(SessionFor::Key(b"k:G"), PACKED, &mut no_notes());
    assert_eq!(import, Err(ErrorKind::BadFunctionArgument));
    assert_eq!(told.uses(), [Kind::SslSessions]);
    assert!(!share.keeps(Kind::SslSessions), "let go");
    // Let go once the export has chosen it.
    let (mut easy, _share, told) = kept_by_a_share();
    easy.share_watch = Some(Emptying::handler(&told, Kind::SslSessions));
    let done = easy
        .ssls_export()
        .deliver::<()>(&mut |_| panic!("no session to give"));
    assert_eq!(done.end(&easy, &mut no_notes()), Ok(()));
    assert_eq!(told.uses(), [Kind::SslSessions]);
}

/// The application's function ends an export with its own value, the lock
/// still let go and nothing said of what was exported.
#[test]
fn an_export_stops_when_told() {
    let (easy, _share, told) = kept_by_a_share();
    easy.ssls_import(SessionFor::Key(b"a:G"), PACKED, &mut no_notes())
        .unwrap();
    easy.ssls_import(SessionFor::Key(b"b:G"), PACKED, &mut no_notes())
        .unwrap();
    told.calls();
    let mut given = 0;
    let done = easy.ssls_export().deliver(&mut |_| {
        given += 1;
        Err(1234)
    });
    assert_eq!(given, 1);
    assert_eq!(told.uses(), [Kind::SslSessions]);
    assert_eq!(
        done.end(&easy, &mut |_, _| panic!("nothing said")),
        Err(ExportFailed::Stopped(1234))
    );
}

/// What it says is C's, under `ssls`, once the lock is let go.
#[test]
fn an_import_and_an_export_trace_as_c_does() {
    let (mut easy, ..) = kept_by_a_share();
    easy.options_mut().output.verbose = true;
    let on = crate::components::Components::new().unwrap();
    on.configure(b"ssls");
    easy.set_components(Some(on));
    let mut lines = Vec::new();
    let mut notes = |_: DebugKind, b: &[u8]| lines.push(String::from_utf8_lossy(b).into_owned());
    assert_eq!(
        easy.ssls_import(SessionFor::Key(b"k:G"), b"x", &mut notes),
        Err(ErrorKind::ReadError)
    );
    easy.ssls_import(SessionFor::SaltedHmac(&[1; 64]), PACKED, &mut notes)
        .unwrap();
    easy.ssls_import(SessionFor::Key(b"k:G"), PACKED, &mut notes)
        .unwrap();
    let done = easy.ssls_export().deliver::<()>(&mut |_| Ok(()));
    done.end(&easy, &mut notes).unwrap();
    assert_eq!(
        lines,
        [
            "[SSLS] error unpacking data: 26\n",
            "[SSLS] successfully imported ticket for peer without key, now with 1 tickets\n",
            "[SSLS] find peer slot for k:G among 25 slots\n",
            "[SSLS] peer not found for k:G\n",
            "[SSLS] successfully imported ticket for peer k:G, now with 1 tickets\n",
            "[SSLS] exported 2 session tickets for 2 peers\n",
        ]
    );
}
