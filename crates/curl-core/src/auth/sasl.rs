//! SASL, as the line protocols log in with it (`lib/curl_sasl.c`, and the
//! messages `lib/vauth` makes): the mechanisms the server offers and the
//! application prefers, the one chosen, and each step of its exchange.
//! Sans-IO: each step says what the protocol is to send, in its own
//! command, and the protocol says what the server answered.

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::auth::creds::Secret;
use crate::hash::{Hash as _, Md5};
use crate::options::AuthMethods;

/// A set of mechanisms (`SASL_MECH_*` bits).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Mechs(u16);

impl Mechs {
    pub(crate) const NONE: Mechs = Mechs(0);
    pub(crate) const LOGIN: Mechs = Mechs(1 << 0);
    pub(crate) const PLAIN: Mechs = Mechs(1 << 1);
    pub(crate) const CRAM_MD5: Mechs = Mechs(1 << 2);
    pub(crate) const DIGEST_MD5: Mechs = Mechs(1 << 3);
    pub(crate) const GSSAPI: Mechs = Mechs(1 << 4);
    pub(crate) const EXTERNAL: Mechs = Mechs(1 << 5);
    pub(crate) const NTLM: Mechs = Mechs(1 << 6);
    pub(crate) const XOAUTH2: Mechs = Mechs(1 << 7);
    pub(crate) const OAUTHBEARER: Mechs = Mechs(1 << 8);
    pub(crate) const SCRAM_SHA_1: Mechs = Mechs(1 << 9);
    pub(crate) const SCRAM_SHA_256: Mechs = Mechs(1 << 10);
    /// Any of them (`SASL_AUTH_DEFAULT`): all but EXTERNAL.
    pub(crate) const DEFAULT: Mechs = Mechs(!(1 << 5));

    pub(crate) fn has(self, m: Mechs) -> bool {
        self.0 & m.0 != 0
    }

    fn and(self, m: Mechs) -> Mechs {
        Mechs(self.0 & m.0)
    }

    pub(crate) fn or(self, m: Mechs) -> Mechs {
        Mechs(self.0 | m.0)
    }

    fn without(self, m: Mechs) -> Mechs {
        Mechs(self.0 & !m.0)
    }
}

/// The mechanisms by name, in C's order (`mechtable`).
const TABLE: [(&str, Mechs); 11] = [
    ("LOGIN", Mechs::LOGIN),
    ("PLAIN", Mechs::PLAIN),
    ("CRAM-MD5", Mechs::CRAM_MD5),
    ("DIGEST-MD5", Mechs::DIGEST_MD5),
    ("GSSAPI", Mechs::GSSAPI),
    ("EXTERNAL", Mechs::EXTERNAL),
    ("NTLM", Mechs::NTLM),
    ("XOAUTH2", Mechs::XOAUTH2),
    ("OAUTHBEARER", Mechs::OAUTHBEARER),
    ("SCRAM-SHA-1", Mechs::SCRAM_SHA_1),
    ("SCRAM-SHA-256", Mechs::SCRAM_SHA_256),
];

/// The mechanism `text` starts with, and its name's length, if it starts
/// with one not run on into a longer word (`Curl_sasl_decode_mech`): the
/// name matched in any case, and followed by nothing, or by a byte that
/// is not an uppercase letter, a digit, `-` or `_`.
pub(crate) fn decode_mech(text: &[u8]) -> Option<(Mechs, usize)> {
    TABLE.iter().find_map(|&(name, bit)| {
        let n = name.len();
        let head = text.get(..n)?;
        if !head.eq_ignore_ascii_case(name.as_bytes()) {
            return None;
        }
        match text.get(n) {
            None => Some((bit, n)),
            Some(&c)
                if !c.is_ascii_uppercase() && !c.is_ascii_digit() && c != b'-' && c != b'_' =>
            {
                Some((bit, n))
            }
            Some(_) => None,
        }
    })
}

/// What a protocol's SASL is (`struct SASLproto`).
#[derive(Debug)]
pub(crate) struct Params {
    /// The service its DIGEST-MD5 URI names (`service`).
    pub(crate) service: &'static str,
    /// The longest a mechanism's name and initial response may be on the
    /// command line together, or no limit (`maxirlen`).
    pub(crate) max_ir: usize,
    /// The mechanisms preferred by default (`defmechs`).
    pub(crate) default: Mechs,
}

/// What the server answered a step with, as the protocol reads its reply
/// (`code` against `contcode` and `finalcode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Code {
    /// The exchange goes on (`contcode`).
    Continue,
    /// The exchange is over, and succeeded (`finalcode`).
    Final,
    /// Neither: the login failed.
    Other,
}

/// What the protocol is to send.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Send {
    /// Its command to start a mechanism, with the initial response if
    /// there is one: empty for one of no bytes, which a protocol may say
    /// as `=` (`sendauth`).
    Auth {
        mech: &'static str,
        initial: Option<Vec<u8>>,
    },
    /// The next response, base64-encoded (`contauth`).
    Continue(Vec<u8>),
    /// The exchange is given up (`cancelauth`).
    Cancel,
}

/// Where the exchange is after a step (`saslprogress`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Progress {
    /// No mechanism could be chosen (`SASL_IDLE`).
    Idle,
    /// A step was taken; `send` goes now (`SASL_INPROGRESS`).
    Sends(Send),
    /// The exchange is over: logged in (`SASL_DONE`).
    Done,
}

/// Why a step failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SaslError {
    /// The server refused the login (`CURLE_LOGIN_DENIED`).
    Denied,
    /// Random bytes could not be had (`Curl_rand_hex`'s failure).
    Random,
    OutOfMemory,
}

impl From<OutOfMemory> for SaslError {
    fn from(OutOfMemory: OutOfMemory) -> SaslError {
        SaslError::OutOfMemory
    }
}

/// Where the exchange stands (`saslstate`), of the mechanisms built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Stop,
    Plain,
    Login,
    LoginPasswd,
    External,
    CramMd5,
    DigestMd5,
    DigestMd5Resp,
    OAuth2,
    OAuth2Resp,
    Cancel,
    Final,
}

impl State {
    /// Its name, as C's debug build says it.
    fn name(self) -> &'static str {
        match self {
            State::Stop => "STOP",
            State::Plain => "PLAIN",
            State::Login => "LOGIN",
            State::LoginPasswd => "LOGIN_PASSWD",
            State::External => "EXTERNAL",
            State::CramMd5 => "CRAMMD5",
            State::DigestMd5 => "DIGESTMD5",
            State::DigestMd5Resp => "DIGESTMD5_RESP",
            State::OAuth2 => "OAUTH2",
            State::OAuth2Resp => "OAUTH2_RESP",
            State::Cancel => "CANCEL",
            State::Final => "FINAL",
        }
    }
}

/// What a step reads beside the server's answer: the connection's
/// credentials, and what C reads of the transfer.
pub(crate) struct Ctx<'a> {
    /// The connection's credentials, if it has any (`conn->creds`).
    pub(crate) creds: Option<Secret<'a>>,
    /// The application asks for an initial response (`CURLOPT_SASL_IR`).
    pub(crate) sasl_ir: bool,
    /// The host and port the connection talks to
    /// (`Curl_conn_get_current_host`).
    pub(crate) host: &'a [u8],
    pub(crate) port: u16,
    /// Random bytes, for DIGEST-MD5's client nonce.
    pub(crate) random: &'a mut dyn FnMut(&mut [u8]) -> Result<(), ()>,
    /// What is said of the exchange, the debug build's lines and the
    /// verbose ones.
    pub(crate) said: &'a mut dyn FnMut(Say, core::fmt::Arguments<'_>),
}

/// Who a line said of the exchange is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Say {
    /// The debug build's alone (`DEBUGBUILD`).
    Debug,
    /// Any verbose transfer (`infof`).
    Info,
}

impl Ctx<'_> {
    fn user(&self) -> &[u8] {
        self.creds.as_ref().map_or(&[][..], Secret::user)
    }

    fn password(&self) -> &[u8] {
        self.creds.as_ref().map_or(&[][..], Secret::password)
    }

    fn has_password(&self) -> bool {
        self.creds
            .as_ref()
            .is_some_and(|c| !c.password().is_empty())
    }

    fn has_bearer(&self) -> bool {
        self.creds.as_ref().is_some_and(Secret::has_bearer)
    }

    fn bearer(&self) -> &[u8] {
        self.creds.as_ref().map_or(&[][..], Secret::bearer)
    }

    fn service<'s>(&'s self, default: &'s str) -> &'s [u8] {
        self.creds
            .as_ref()
            .and_then(Secret::service)
            .unwrap_or(default.as_bytes())
    }
}

/// A connection's SASL (`struct SASL`).
#[derive(Debug)]
pub(crate) struct Sasl {
    params: &'static Params,
    state: State,
    /// The mechanism in use (`curmech`).
    current: Option<&'static str>,
    /// What the server offers (`authmechs`).
    offered: Mechs,
    /// What the application prefers (`prefmech`).
    preferred: Mechs,
    /// What was used (`authused`).
    used: Mechs,
    /// The URL's first `AUTH=` replaces the preferences (`resetprefs`).
    reset_prefs: bool,
    /// An initial response is sent whatever the application says
    /// (`force_ir`).
    force_ir: bool,
}

impl Sasl {
    /// Set up for `params`, the preferences from the methods the
    /// application allows HTTP if they are not Basic's alone
    /// (`Curl_sasl_init`).
    pub(crate) fn new(params: &'static Params, http: AuthMethods) -> Sasl {
        let mut preferred = params.default;
        if http != AuthMethods::BASIC {
            let mut mechs = Mechs::NONE;
            if http.contains(AuthMethods::BASIC) {
                mechs = mechs.or(Mechs::PLAIN).or(Mechs::LOGIN);
            }
            if http.contains(AuthMethods::DIGEST) {
                mechs = mechs.or(Mechs::DIGEST_MD5);
            }
            if http.contains(AuthMethods::BEARER) {
                mechs = mechs.or(Mechs::OAUTHBEARER).or(Mechs::XOAUTH2);
            }
            if http.contains(AuthMethods::NEGOTIATE) {
                mechs = mechs.or(Mechs::GSSAPI);
            }
            if mechs != Mechs::NONE {
                preferred = mechs;
            }
        }
        Sasl {
            params,
            state: State::Stop,
            current: None,
            offered: Mechs::NONE,
            preferred,
            used: Mechs::NONE,
            reset_prefs: true,
            force_ir: false,
        }
    }

    /// The preferences none: no SASL (a POP3 URL's `AUTH=+APOP`).
    pub(crate) fn prefer_none(&mut self) {
        self.preferred = Mechs::NONE;
    }

    /// What the application prefers.
    pub(crate) fn preferred(&self) -> Mechs {
        self.preferred
    }

    /// The server's capabilities are read afresh: it offers none yet,
    /// and none is used.
    pub(crate) fn forget_offers(&mut self) {
        self.offered = Mechs::NONE;
        self.used = Mechs::NONE;
    }

    /// No mechanism is used, what the server offers kept: SMTP's `HELO`,
    /// which logs in with none (`authused`).
    pub(crate) fn forget_used(&mut self) {
        self.used = Mechs::NONE;
    }

    /// Whether a mechanism was used to log in (`authused`).
    pub(crate) fn used_any(&self) -> bool {
        self.used != Mechs::NONE
    }

    /// The server offers `mechs` too.
    pub(crate) fn offers(&mut self, mechs: Mechs) {
        self.offered = self.offered.or(mechs);
    }

    /// A URL's `AUTH=` value (`Curl_sasl_parse_url_auth_option`): `*` for
    /// any, or a mechanism's name, added to the preferences the first
    /// replaced. Whether it was one.
    pub(crate) fn url_auth(&mut self, value: &[u8]) -> bool {
        if value.is_empty() {
            return false;
        }
        if self.reset_prefs {
            self.reset_prefs = false;
            self.preferred = Mechs::NONE;
        }
        if value == b"*" {
            self.preferred = Mechs::DEFAULT;
            return true;
        }
        match decode_mech(value) {
            Some((bit, n)) if n == value.len() => {
                self.preferred = self.preferred.or(bit);
                true
            }
            _ => false,
        }
    }

    /// Whether there is anything to log in with (`Curl_sasl_can_authenticate`).
    pub(crate) fn can_authenticate(&self, cx: &Ctx<'_>) -> bool {
        cx.creds.is_some() || self.offered.and(self.preferred).has(Mechs::EXTERNAL)
    }

    fn set_state(&mut self, cx: &mut Ctx<'_>, state: State) {
        if self.state != state {
            (cx.said)(
                Say::Debug,
                format_args!(
                    "SASL {:p} state change from {} to {}",
                    self as *const Sasl,
                    self.state.name(),
                    state.name()
                ),
            );
        }
        self.state = state;
    }

    /// Choose the most secure mechanism both ends allow and start it
    /// (`Curl_sasl_start`).
    pub(crate) fn start(
        &mut self,
        cx: &mut Ctx<'_>,
        force_ir: bool,
    ) -> Result<Progress, SaslError> {
        self.force_ir = force_ir;
        self.used = Mechs::NONE;
        let enabled = self.offered.and(self.preferred);
        let ir = force_ir || cx.sasl_ir;
        let (mech, bit, first, then, resp): (&'static str, _, _, _, Option<Vec<u8>>) =
            if enabled.has(Mechs::EXTERNAL) && !cx.has_password() {
                let resp = ir.then(|| copy(cx.user())).transpose()?;
                (
                    "EXTERNAL",
                    Mechs::EXTERNAL,
                    State::External,
                    State::Final,
                    resp,
                )
            } else if enabled.has(Mechs::DIGEST_MD5) {
                (
                    "DIGEST-MD5",
                    Mechs::DIGEST_MD5,
                    State::DigestMd5,
                    State::Final,
                    None,
                )
            } else if enabled.has(Mechs::CRAM_MD5) {
                (
                    "CRAM-MD5",
                    Mechs::CRAM_MD5,
                    State::CramMd5,
                    State::Final,
                    None,
                )
            } else if cx.has_bearer() && enabled.has(Mechs::OAUTHBEARER) {
                let resp = ir.then(|| oauth_bearer(cx)).transpose()?;
                (
                    "OAUTHBEARER",
                    Mechs::OAUTHBEARER,
                    State::OAuth2,
                    State::OAuth2Resp,
                    resp,
                )
            } else if cx.has_bearer() && enabled.has(Mechs::XOAUTH2) {
                let resp = ir.then(|| xoauth2(cx)).transpose()?;
                ("XOAUTH2", Mechs::XOAUTH2, State::OAuth2, State::Final, resp)
            } else if enabled.has(Mechs::PLAIN) {
                let resp = ir.then(|| plain(cx)).transpose()?;
                ("PLAIN", Mechs::PLAIN, State::Plain, State::Final, resp)
            } else if enabled.has(Mechs::LOGIN) {
                let resp = ir.then(|| copy(cx.user())).transpose()?;
                (
                    "LOGIN",
                    Mechs::LOGIN,
                    State::Login,
                    State::LoginPasswd,
                    resp,
                )
            } else {
                return Ok(Progress::Idle);
            };
        self.used = bit;
        self.current = Some(mech);
        let mut initial = resp.map(|r| base64(&r)).transpose()?;
        if self.params.max_ir > 0
            && initial
                .as_ref()
                .is_some_and(|i| mech.len() + i.len() > self.params.max_ir)
        {
            initial = None;
        }
        let state = if initial.is_some() { then } else { first };
        self.set_state(cx, state);
        Ok(Progress::Sends(Send::Auth { mech, initial }))
    }

    /// Take the server's answer to the last step, `code` and its
    /// `message` as the protocol finds it, still encoded, and take the
    /// next (`Curl_sasl_continue`).
    pub(crate) fn step(
        &mut self,
        cx: &mut Ctx<'_>,
        code: Code,
        message: &[u8],
    ) -> Result<Progress, SaslError> {
        if self.state == State::Final {
            self.set_state(cx, State::Stop);
            return if code == Code::Final {
                Ok(Progress::Done)
            } else {
                Err(SaslError::Denied)
            };
        }
        if self.state != State::Cancel && self.state != State::OAuth2Resp && code != Code::Continue
        {
            self.set_state(cx, State::Stop);
            return Err(SaslError::Denied);
        }
        let mut next = State::Final;
        // `None` is a challenge that cannot be read: the exchange is
        // cancelled (`CURLE_BAD_CONTENT_ENCODING`).
        let resp: Option<Vec<u8>> = match self.state {
            State::Stop => return Ok(Progress::Done),
            State::Plain => Some(plain(cx)?),
            State::Login => {
                next = State::LoginPasswd;
                Some(copy(cx.user())?)
            }
            State::LoginPasswd => Some(copy(cx.password())?),
            State::External => Some(copy(cx.user())?),
            State::CramMd5 => match server_message(message)? {
                Some(chlg) => Some(cram_md5(cx, &chlg)?),
                None => None,
            },
            State::DigestMd5 => match server_message(message)? {
                Some(chlg) => {
                    next = State::DigestMd5Resp;
                    digest_md5(cx, &chlg, self.params.service)?
                }
                None => None,
            },
            // An empty line.
            State::DigestMd5Resp => Some(Vec::new()),
            State::OAuth2 if self.used == Mechs::OAUTHBEARER => {
                // A failure may come as a continuation.
                next = State::OAuth2Resp;
                Some(oauth_bearer(cx)?)
            }
            State::OAuth2 => Some(xoauth2(cx)?),
            State::OAuth2Resp => match code {
                Code::Final => {
                    self.set_state(cx, State::Stop);
                    return Ok(Progress::Done);
                }
                // Acknowledged with a byte of 1.
                Code::Continue => Some(copy(b"\x01")?),
                Code::Other => {
                    self.set_state(cx, State::Stop);
                    return Err(SaslError::Denied);
                }
            },
            State::Cancel => {
                // The mechanism refused is not tried again; another is.
                self.offered = self.offered.without(self.used);
                self.used = Mechs::NONE;
                self.current = None;
                return self.start(cx, self.force_ir);
            }
            State::Final => unreachable!("answered above"),
        };
        match resp {
            None => {
                self.set_state(cx, State::Cancel);
                Ok(Progress::Sends(Send::Cancel))
            }
            Some(resp) => {
                let encoded = base64(&resp)?;
                self.set_state(cx, next);
                Ok(Progress::Sends(Send::Continue(encoded)))
            }
        }
    }

    /// Why no mechanism could be chosen, said as C says it, the login then
    /// failing (`Curl_sasl_is_blocked`).
    pub(crate) fn blocked(&self, cx: &mut Ctx<'_>) {
        let has_user = !cx.user().is_empty();
        let has_password = cx.has_password();
        let has_bearer = cx.has_bearer();
        let mut say = |args: core::fmt::Arguments<'_>| (cx.said)(Say::Info, args);
        let say = &mut say;
        let enabled = self.offered.and(self.preferred);
        if self.offered == Mechs::NONE {
            say(format_args!(
                "SASL: no auth mechanism was offered or recognized"
            ));
            return;
        }
        if enabled == Mechs::NONE {
            say(format_args!(
                "SASL: no overlap between offered and configured auth mechanisms"
            ));
            return;
        }
        say(format_args!(
            "SASL: no auth mechanism offered could be selected"
        ));
        if enabled.has(Mechs::EXTERNAL) && has_password {
            say(format_args!("SASL: auth EXTERNAL not chosen with password"));
        }
        let unchosen = |say: &mut dyn FnMut(core::fmt::Arguments<'_>),
                        mech: Mechs,
                        built: bool,
                        platform: bool,
                        missing: Option<&str>| {
            if !enabled.has(mech) {
                return;
            }
            let name = TABLE
                .iter()
                .find(|(_, bit)| *bit == mech)
                .map(|(n, _)| *n)
                .expect("each mechanism is in the table");
            if !built {
                say(format_args!("SASL: {name} not builtin"));
            } else if !platform {
                say(format_args!(
                    "SASL: {name} not supported by the platform/libraries"
                ));
            } else {
                if let Some(missing) = missing {
                    say(format_args!("SASL: {name} is missing {missing}"));
                }
                if !has_user {
                    say(format_args!("SASL: {name} is missing username"));
                }
            }
        };
        let bearer = (!has_bearer).then_some("CURLOPT_XOAUTH2_BEARER");
        unchosen(say, Mechs::GSSAPI, false, false, None);
        unchosen(say, Mechs::SCRAM_SHA_256, false, false, None);
        unchosen(say, Mechs::SCRAM_SHA_1, false, false, None);
        unchosen(say, Mechs::DIGEST_MD5, true, true, None);
        unchosen(say, Mechs::CRAM_MD5, true, true, None);
        unchosen(say, Mechs::NTLM, false, false, None);
        unchosen(say, Mechs::OAUTHBEARER, true, true, bearer);
        unchosen(say, Mechs::XOAUTH2, true, true, bearer);
    }
}

fn copy(bytes: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut v = Vec::new();
    v.try_extend_from_slice(bytes)?;
    Ok(v)
}

fn join(parts: &[&[u8]]) -> Result<Vec<u8>, OutOfMemory> {
    let mut v = Vec::new();
    v.try_reserve_exact(parts.iter().map(|p| p.len()).sum())
        .map_err(|_| OutOfMemory)?;
    for part in parts {
        v.try_extend_from_slice(part)?;
    }
    Ok(v)
}

/// A message encoded to go (`build_message`): base64, none for none.
fn base64(bytes: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut out = Vec::new();
    crate::base64::encode(bytes.iter().copied(), bytes.len(), &mut out)?;
    Ok(out)
}

/// The server's challenge decoded (`get_server_message`): an empty one is
/// no bytes; `None` if it is not base64.
fn server_message(message: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
    if message.is_empty() {
        return Ok(Some(Vec::new()));
    }
    crate::base64::decode(message)
}

/// PLAIN's message: the identity acted for, the user and the password,
/// each after a zero byte but the first (`Curl_auth_create_plain_message`).
fn plain(cx: &Ctx<'_>) -> Result<Vec<u8>, OutOfMemory> {
    let authzid = cx.creds.as_ref().map_or(&[][..], Secret::authzid);
    join(&[authzid, b"\0", cx.user(), b"\0", cx.password()])
}

/// OAUTHBEARER's message (RFC 7628), the port left out if it is 80 or
/// none (`Curl_auth_create_oauth_bearer_message`).
fn oauth_bearer(cx: &Ctx<'_>) -> Result<Vec<u8>, OutOfMemory> {
    // The port in decimal, at most five digits.
    let mut digits = [0u8; 5];
    let mut at = digits.len();
    let mut n = cx.port;
    loop {
        at -= 1;
        digits[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let port: &[&[u8]] = if cx.port == 0 || cx.port == 80 {
        &[]
    } else {
        &[b"port=", &digits[at..], b"\x01"]
    };
    let mut parts: Vec<&[u8]> = Vec::new();
    parts.try_extend_from_slice(&[b"n,a=", cx.user(), b",\x01host=", cx.host, b"\x01"])?;
    parts.try_extend_from_slice(port)?;
    parts.try_extend_from_slice(&[b"auth=Bearer ", cx.bearer(), b"\x01\x01"])?;
    join(&parts)
}

/// XOAUTH2's message (`Curl_auth_create_xoauth_bearer_message`).
fn xoauth2(cx: &Ctx<'_>) -> Result<Vec<u8>, OutOfMemory> {
    join(&[
        b"user=",
        cx.user(),
        b"\x01auth=Bearer ",
        cx.bearer(),
        b"\x01\x01",
    ])
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len() * 2)
        .map_err(|_| OutOfMemory)?;
    for b in bytes {
        out.try_extend_from_slice(&[HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]])?;
    }
    Ok(out)
}

/// The MD5 of `parts` joined.
fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md5::default();
    for part in parts {
        h.update(part);
    }
    let mut out = [0; 16];
    out.copy_from_slice(&h.finish()[..16]);
    out
}

/// CRAM-MD5's message: the user and the HMAC-MD5 of the challenge under
/// the password, in hex (`Curl_auth_create_cram_md5_message`).
fn cram_md5(cx: &Ctx<'_>, chlg: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let digest = crate::hash::hmac_md5(cx.password(), &[chlg]);
    join(&[cx.user(), b" ", &hex(&digest)?])
}

/// The value of `key` in a DIGEST-MD5 challenge, its quotes and
/// backslashes undone; none if the challenge does not have it, or is
/// odd before it (`auth_digest_get_key_value`). A value no shorter than
/// `max` does not fit.
fn digest_value(mut chlg: &[u8], key: &[u8], max: usize) -> Option<Vec<u8>> {
    loop {
        while let [b' ' | b'\t', rest @ ..] = chlg {
            chlg = rest;
        }
        let eq = chlg.iter().position(|&b| b == b'=')?;
        if eq == 0 || eq > 64 {
            return None;
        }
        let name = &chlg[..eq];
        chlg = &chlg[eq + 1..];
        // A quoted word, or else up to a comma.
        let data: &[u8] = if let [b'"', rest @ ..] = chlg {
            let mut i = 0;
            let mut len = 0;
            while i < rest.len() && rest[i] != b'"' {
                if rest[i] == b'\\' && i + 1 < rest.len() {
                    i += 1;
                    len += 1;
                }
                i += 1;
                len += 1;
                if len > 256 {
                    return None;
                }
            }
            if i >= rest.len() {
                return None;
            }
            let data = &rest[..i];
            chlg = &rest[i + 1..];
            data
        } else {
            let end = chlg.iter().position(|&b| b == b',').unwrap_or(chlg.len());
            if end == 0 || end > 256 {
                return None;
            }
            let data = &chlg[..end];
            chlg = &chlg[end..];
            data
        };
        if name == key {
            if data.len() >= max {
                return None;
            }
            let mut out = Vec::new();
            let mut i = 0;
            while i < data.len() {
                if data[i] == b'\\' && i + 1 < data.len() {
                    i += 1;
                }
                out.try_push(data[i]).ok()?;
                i += 1;
            }
            return Some(out);
        }
        match chlg {
            [b',', rest @ ..] => chlg = rest,
            _ => return None,
        }
    }
}

/// `s` quoted as RFC 2616's errata quote a string: `"` and `\` escaped,
/// other bytes outside printable ASCII as `%XX`
/// (`auth_digest_string_quoted`).
fn quoted(s: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut out = Vec::new();
    for &b in s {
        match b {
            b'"' | b'\\' => out.try_extend_from_slice(&[b'\\', b])?,
            0x20..=0x7e => out.try_push(b)?,
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.try_extend_from_slice(&[
                    b'%',
                    HEX[usize::from(b >> 4)],
                    HEX[usize::from(b & 15)],
                ])?;
            }
        }
    }
    Ok(out)
}

/// DIGEST-MD5's response (RFC 2831) to `chlg`, or `None` if the
/// challenge is not one it answers: md5-sess, `auth`
/// (`Curl_auth_create_digest_md5_message`).
fn digest_md5(cx: &mut Ctx<'_>, chlg: &[u8], service: &str) -> Result<Option<Vec<u8>>, SaslError> {
    // Read as C reads it, a string: up to a zero byte.
    let chlg = chlg.split(|&b| b == 0).next().unwrap_or_default();
    if chlg.is_empty() {
        return Ok(None);
    }
    let Some(nonce) = digest_value(chlg, b"nonce", 64) else {
        return Ok(None);
    };
    let realm = digest_value(chlg, b"realm", 128).unwrap_or_default();
    let Some(algorithm) = digest_value(chlg, b"algorithm", 64) else {
        return Ok(None);
    };
    let Some(qop) = digest_value(chlg, b"qop", 64) else {
        return Ok(None);
    };
    if algorithm != b"md5-sess" {
        return Ok(None);
    }
    // `auth` among the options, each up to a comma.
    let auth = qop
        .split(|&b| b == b',')
        .take_while(|w| !w.is_empty() && w.len() <= 32)
        .any(|w| w.eq_ignore_ascii_case(b"auth"));
    if !auth {
        return Ok(None);
    }
    let mut random = [0u8; 16];
    (cx.random)(&mut random).map_err(|()| SaslError::Random)?;
    let cnonce = hex(&random)?;
    let (user, password) = (cx.user(), cx.password());
    let a1 = md5(&[user, b":", &realm, b":", password]);
    let ha1 = hex(&md5(&[&a1, b":", &nonce, b":", &cnonce]))?;
    let spn = join(&[cx.service(service), b"/", cx.host])?;
    let ha2 = hex(&md5(&[b"AUTHENTICATE:", &spn]))?;
    let response = hex(&md5(&[
        &ha1,
        b":",
        &nonce,
        b":",
        b"00000001",
        b":",
        &cnonce,
        b":",
        b"auth",
        b":",
        &ha2,
    ]))?;
    Ok(Some(join(&[
        b"username=\"",
        &quoted(user)?,
        b"\",realm=\"",
        &quoted(&realm)?,
        b"\",nonce=\"",
        &quoted(&nonce)?,
        b"\",cnonce=\"",
        &cnonce,
        b"\",nc=\"00000001\",digest-uri=\"",
        &quoted(&spn)?,
        b"\",response=",
        &response,
        b",qop=auth",
    ])?))
}

#[cfg(test)]
mod tests;
