//! Authenticating HTTP requests (`lib/http.c`'s `Curl_http_output_auth`,
//! `Curl_http_input_auth` and `Curl_http_auth_act`): Basic, with the
//! credentials the options or the URL carry (`url_set_data_creds`), sent
//! at once or once a server's challenge asks for it.

use curl_alloc::{OutOfMemory, TryVec as _};

use super::request::Trusted;
use crate::error::UrlErrorKind;
use crate::options::{AuthMethods, Login};
use crate::url::{GetOptions, Part, Url, decode_but_zero};

/// Authenticating with the origin, over a handle's transfers (C's
/// `state.authhost` and `state.authproblem`).
#[derive(Debug, Default)]
pub(crate) struct HostAuth {
    /// The methods the transfer may use.
    want: AuthMethods,
    /// The method chosen; before a server asked, the wanted set. Kept
    /// from one transfer to the next, as the handle keeps it.
    picked: AuthMethods,
    /// Authenticating is as far as it goes.
    done: bool,
    /// The credentials were refused, or none fit the challenge.
    problem: bool,
}

/// What a request sends to authenticate.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Output {
    /// The method whose header goes, if any.
    pub(crate) sent: Option<AuthMethods>,
    /// The method chosen so far, for the report (`info.httpauthpicked`).
    pub(crate) used: AuthMethods,
    /// The request goes without its body, a probe for a method that
    /// takes more than one (`req.authneg`).
    pub(crate) probe: bool,
}

impl HostAuth {
    /// A transfer starts, wanting `want` (`Curl_pretransfer`).
    pub(crate) fn start(&mut self, want: AuthMethods) {
        self.problem = false;
        self.want = want;
        self.picked = self.picked & want;
    }

    /// What a request with `credentials` sends to authenticate with the
    /// origin (`Curl_http_output_auth`, `output_auth_headers`). `custom`
    /// says the application sends its own Authorization, which Basic
    /// does not replace.
    pub(crate) fn output(
        &mut self,
        credentials: Option<&Credentials>,
        custom: bool,
        get_or_head: bool,
    ) -> Output {
        let nothing = Output {
            sent: None,
            used: AuthMethods::NONE,
            probe: false,
        };
        let Some(credentials) = credentials else {
            self.done = true;
            return nothing;
        };
        if !self.want.is_empty() && self.picked.is_empty() {
            // Before a server asks: one method wanted is used at once.
            self.picked = self.want;
        }
        let sent = match self.picked.single() {
            Some(AuthMethods::BASIC) => {
                self.done = true;
                (credentials.has_user_or_password() && !custom).then_some(AuthMethods::BASIC)
            }
            _ => None,
        };
        // A method that takes more than one request, not done, probes
        // without the body; none does yet.
        let multipass = sent.is_some() && !self.done;
        Output {
            sent,
            used: if sent.is_some() {
                self.picked
            } else {
                AuthMethods::NONE
            },
            probe: multipass && !get_or_head,
        }
    }

    /// What a request asks of its response's challenges.
    pub(crate) fn asked(
        &self,
        credentials: Option<&Credentials>,
        probe: bool,
        get_or_head: bool,
    ) -> AuthAsked {
        AuthAsked {
            want: self.want,
            picked: self.picked,
            credentials: credentials.is_some(),
            user_or_password: credentials.is_some_and(Credentials::has_user_or_password),
            done: self.done,
            probe,
            get_or_head,
            problem: self.problem,
        }
    }

    /// What a response's challenges led to (`Curl_http_auth_act`).
    pub(crate) fn apply(&mut self, act: &AuthAct) {
        if let Some(picked) = act.picked {
            self.picked = picked;
        }
        self.problem = act.problem;
        self.done |= act.done;
    }
}

/// What a request knows of authenticating, for its response to act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuthAsked {
    want: AuthMethods,
    picked: AuthMethods,
    /// The request has credentials, empty ones too.
    credentials: bool,
    user_or_password: bool,
    done: bool,
    probe: bool,
    get_or_head: bool,
    problem: bool,
}

impl AuthAsked {
    /// A request without credentials, wanting nothing.
    pub(crate) const DEFAULT: AuthAsked = AuthAsked {
        want: AuthMethods::NONE,
        picked: AuthMethods::NONE,
        credentials: false,
        user_or_password: false,
        done: false,
        probe: false,
        get_or_head: true,
        problem: false,
    };
}

impl Default for AuthAsked {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What the challenges of a response offered (`Curl_http_input_auth`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Challenges {
    /// The methods offered that are still open: a refusal closes them.
    open: AuthMethods,
    /// Every method offered, for the report (`info.httpauthavail`).
    pub(crate) offered: AuthMethods,
    /// The method used was offered again: the credentials were refused.
    refused: bool,
}

impl Challenges {
    /// A `WWW-Authenticate:` value, its methods one after another,
    /// separated by commas. Gives the method whose credentials it
    /// refuses, if it does.
    pub(crate) fn read(&mut self, mut value: &[u8], asked: &AuthAsked) -> Option<AuthMethods> {
        let mut refused = None;
        while !value.is_empty() {
            for method in [AuthMethods::BASIC, AuthMethods::BEARER] {
                if names(value, method.name()) {
                    self.offered = self.offered | method;
                    self.open = self.open | method;
                    if asked.picked == method {
                        // Asked for and offered again anyway: refused.
                        self.open = AuthMethods::NONE;
                        self.refused = true;
                        refused = Some(method);
                    }
                }
            }
            let Some(comma) = value.iter().position(|&b| b == b',') else {
                break;
            };
            value = &value[comma + 1..];
            let blanks = value
                .iter()
                .take_while(|&&b| b == b' ' || b == b'\t')
                .count();
            value = &value[blanks..];
        }
        refused
    }
}

/// Whether `value` starts with the method `name`, not followed by a
/// letter or digit (`authcmp`).
fn names(value: &[u8], name: &str) -> bool {
    let name = name.as_bytes();
    value.len() >= name.len()
        && value[..name.len()].eq_ignore_ascii_case(name)
        && !value.get(name.len()).is_some_and(u8::is_ascii_alphanumeric)
}

/// What a final response leads to, once its head is in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AuthAct {
    /// The method chosen, none if none fits, when one was chosen.
    pub(crate) picked: Option<AuthMethods>,
    pub(crate) problem: bool,
    /// The request is made again, its body not delivered.
    pub(crate) reload: bool,
    pub(crate) done: bool,
}

impl AuthAct {
    /// What a response with `code` and these `challenges` leads to, for
    /// a request that asked `asked` (`Curl_http_auth_act`, `pickoneauth`).
    pub(crate) fn of(code: u16, challenges: &Challenges, asked: &AuthAsked) -> AuthAct {
        let mut act = AuthAct {
            problem: asked.problem || challenges.refused,
            ..AuthAct::default()
        };
        if act.problem {
            return act;
        }
        if asked.credentials && (code == 401 || asked.probe && code < 300) {
            let open = challenges.open & asked.want & !AuthMethods::BEARER;
            // In C's order of preference.
            let picked = if open.contains(AuthMethods::BASIC) && asked.user_or_password {
                AuthMethods::BASIC
            } else {
                AuthMethods::NONE
            };
            act.picked = Some(picked);
            act.problem = picked.is_empty();
            act.reload = !picked.is_empty();
        } else if code < 300 && !asked.done && asked.probe && !asked.get_or_head {
            act.reload = true;
            act.done = true;
        }
        act
    }

    /// Whether a 401 or 407 is an error to fail on, as other codes of 400
    /// or more are (`http_should_fail`): one asking for credentials the
    /// request has, not yet refused, is not.
    pub(crate) fn fails(&self, code: u16, asked: &AuthAsked) -> bool {
        match code {
            401 => !asked.credentials || self.problem,
            // No proxy credentials yet.
            407 => true,
            _ => true,
        }
    }
}

/// The user and password a request authenticates with, decoded (C's
/// `struct Curl_creds`), and the leave to send them to its origin.
#[derive(Debug)]
pub(crate) struct Credentials {
    user: Vec<u8>,
    password: Vec<u8>,
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "netrc reads it, MILESTONES step 29")
    )]
    source: Source,
    trusted: Trusted,
}

/// Where credentials came from (`CREDS_*`): the last that gave any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    Options,
    Url,
}

/// Why a URL's credentials could not be taken.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CredentialsError {
    OutOfMemory,
    /// One decodes to a zero byte: "error extracting credentials from URL".
    Malformed,
}

impl From<OutOfMemory> for CredentialsError {
    fn from(_: OutOfMemory) -> Self {
        CredentialsError::OutOfMemory
    }
}

impl Credentials {
    /// What a request to `url` authenticates with (`url_set_data_creds`):
    /// the application's `login`, if `trusted` lets it go to the URL's
    /// origin; then what the URL carries, if the login named no user,
    /// each part it has replacing the login's.
    pub(crate) fn for_request(
        login: &Login,
        trusted: Option<Trusted>,
        url: &Url,
    ) -> Result<Option<Credentials>, CredentialsError> {
        let (mut user, mut password) = (None, None);
        if let Some(trusted) = trusted {
            user = login.user.as_deref().map(copy).transpose()?;
            password = login.password.as_deref().map(copy).transpose()?;
            if let Some(user) = user.take_if(|u| !u.is_empty()) {
                return Ok(Some(Credentials {
                    user,
                    password: password.unwrap_or_default(),
                    source: Source::Options,
                    trusted,
                }));
            }
        }
        if let Some((url_user, url_password)) = Self::of_url(url)? {
            user = url_user.or(user);
            password = url_password.or(password);
        } else if user.is_none() && password.is_none() {
            return Ok(None);
        }
        // What the login left blank merged with the URL is the URL's,
        // even where the URL had nothing (`Curl_creds_merge`).
        Ok(Some(Credentials {
            user: user.unwrap_or_default(),
            password: password.unwrap_or_default(),
            source: Source::Url,
            // A login gets this far only trusted; the URL's own always.
            trusted: trusted.unwrap_or_else(Trusted::own_url),
        }))
    }

    /// What `url` carries, if it has a user or a password: decoded,
    /// rejecting a zero byte (HTTP allows other control bytes,
    /// `PROTOPT_USERPWDCTRL`).
    #[expect(
        clippy::type_complexity,
        reason = "a user and a password, each there or not"
    )]
    fn of_url(url: &Url) -> Result<Option<(Option<Vec<u8>>, Option<Vec<u8>>)>, CredentialsError> {
        let part = |what, missing| match url.get(what, GetOptions::NONE) {
            Ok(raw) => match decode_but_zero(&raw) {
                Ok(Some(decoded)) => Ok(Some(decoded)),
                Ok(None) => Err(CredentialsError::Malformed),
                Err(_) => Err(CredentialsError::OutOfMemory),
            },
            Err(e) if e == missing => Ok(None),
            Err(UrlErrorKind::OutOfMemory) => Err(CredentialsError::OutOfMemory),
            Err(_) => Err(CredentialsError::Malformed),
        };
        let user = part(Part::User, UrlErrorKind::NoUser)?;
        let password = part(Part::Password, UrlErrorKind::NoPassword)?;
        if user.is_none() && password.is_none() {
            return Ok(None);
        }
        Ok(Some((user, password)))
    }

    pub(crate) fn user(&self) -> &[u8] {
        &self.user
    }

    /// A user or a password, not both empty (`Curl_creds_has_user_or_pass`).
    pub(crate) fn has_user_or_password(&self) -> bool {
        !self.user.is_empty() || !self.password.is_empty()
    }

    /// The leave to send these to the request's origin.
    pub(crate) fn trusted(&self) -> Trusted {
        self.trusted
    }

    /// `user:password` in base64, what `Authorization: Basic` carries;
    /// nothing when both are empty (`Curl_creds_has_user_or_pass`).
    pub(crate) fn basic(&self) -> Result<Option<Vec<u8>>, OutOfMemory> {
        if self.user.is_empty() && self.password.is_empty() {
            return Ok(None);
        }
        let len = self.user.len() + 1 + self.password.len();
        let mut out = Vec::new();
        out.try_reserve_exact(len.div_ceil(3) * 4)
            .map_err(|_| OutOfMemory)?;
        let bytes = self.user.iter().chain(b":").chain(&self.password).copied();
        base64(bytes, len, &mut out)?;
        Ok(Some(out))
    }
}

fn copy(bytes: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut v = Vec::new();
    v.try_extend_from_slice(bytes).map_err(|_| OutOfMemory)?;
    Ok(v)
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `len` bytes from `bytes` in base64 with padding, into `out`.
fn base64(
    mut bytes: impl Iterator<Item = u8>,
    len: usize,
    out: &mut Vec<u8>,
) -> Result<(), OutOfMemory> {
    for _ in 0..len.div_ceil(3) {
        let group = [bytes.next(), bytes.next(), bytes.next()];
        let n = group
            .iter()
            .fold(0u32, |n, b| n << 8 | u32::from(b.unwrap_or(0)));
        let have = group.iter().filter(|b| b.is_some()).count();
        for i in 0..4 {
            let c = if i <= have {
                ALPHABET[(n >> (18 - 6 * i) & 0x3f) as usize]
            } else {
                b'='
            };
            out.try_push(c)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::url::ParseOptions;

    /// A user and a password.
    type Pair = (Vec<u8>, Vec<u8>);

    fn creds(url: &str) -> Result<Option<Pair>, CredentialsError> {
        with(&Login::default(), true, url).map(|c| c.map(|(u, p, _)| (u, p)))
    }

    #[expect(clippy::type_complexity, reason = "a test's view")]
    fn with(
        login: &Login,
        trusted: bool,
        url: &str,
    ) -> Result<Option<(Vec<u8>, Vec<u8>, Source)>, CredentialsError> {
        let url = Url::parse(url.as_bytes(), ParseOptions::NONE).unwrap();
        let trusted = trusted.then(Trusted::own_url);
        Ok(Credentials::for_request(login, trusted, &url)?.map(|c| (c.user, c.password, c.source)))
    }

    /// As C's `url_set_data_creds` composes them: the login's user wins
    /// whole; with none, the URL's parts replace the login's; an
    /// untrusted login is not looked at.
    #[test]
    fn composes_the_login_and_the_url_s_as_c() {
        let login = |u: Option<&[u8]>, p: Option<&[u8]>| Login {
            user: u.map(<[u8]>::to_vec),
            password: p.map(<[u8]>::to_vec),
        };
        let got = |u: &[u8], p: &[u8], s| Ok(Some((u.to_vec(), p.to_vec(), s)));
        let both = login(Some(b"smith"), Some(b"doggie"));
        assert_eq!(
            with(&both, true, "http://first:secret@h/"),
            got(b"smith", b"doggie", Source::Options)
        );
        assert_eq!(
            with(&both, false, "http://first:secret@h/"),
            got(b"first", b"secret", Source::Url)
        );
        assert_eq!(with(&both, false, "http://h/"), Ok(None));
        let no_user = login(Some(b""), Some(b"pw"));
        assert_eq!(
            with(&no_user, true, "http://u@h/"),
            got(b"u", b"pw", Source::Url)
        );
        assert_eq!(
            with(&no_user, true, "http://h/"),
            got(b"", b"pw", Source::Url)
        );
        // `CURLOPT_USERPWD` splits at the first colon.
        let pair = Login::from_pair(b"a:b:c").unwrap();
        assert_eq!(
            (pair.user, pair.password),
            (Some(b"a".to_vec()), Some(b"b:c".to_vec()))
        );
        let pair = Login::from_pair(b"a").unwrap();
        assert_eq!((pair.user, pair.password), (Some(b"a".to_vec()), None));
        let user_alone = login(Some(b"smith"), None);
        assert_eq!(
            with(&user_alone, true, "http://first:secret@h/"),
            got(b"smith", b"", Source::Options)
        );
    }

    /// As the C tool takes them from `http://USERINFO@host/`.
    #[test]
    fn takes_the_url_s_credentials_as_c() {
        let some = |u: &[u8], p: &[u8]| Ok(Some((u.to_vec(), p.to_vec())));
        assert_eq!(creds("http://h/"), Ok(None));
        assert_eq!(creds("http://:example@h/"), some(b"", b"example"));
        assert_eq!(creds("http://u@h/"), some(b"u", b""));
        assert_eq!(creds("http://u:@h/"), some(b"u", b""));
        assert_eq!(creds("http://@h/"), some(b"", b""));
        assert_eq!(creds("http://a%01b:x%3a@h/"), some(b"a\x01b", b"x:"));
        assert_eq!(creds("http://a%00b:x@h/"), Err(CredentialsError::Malformed));
        assert_eq!(creds("http://a:%00@h/"), Err(CredentialsError::Malformed));
    }

    /// Methods are read at the start of each comma-separated part, whole
    /// words only, in any case; the one used offered again is refused,
    /// and closes what was open.
    #[test]
    fn reads_challenges_as_c() {
        let read = |values: &[&[u8]], picked| {
            let asked = AuthAsked {
                picked,
                ..AuthAsked::DEFAULT
            };
            let mut c = Challenges::default();
            let refused: Vec<_> = values.iter().filter_map(|v| c.read(v, &asked)).collect();
            (c.open, c.offered, refused)
        };
        let none = AuthMethods::NONE;
        let (b, br) = (AuthMethods::BASIC, AuthMethods::BEARER);
        assert_eq!(read(&[b"Basic realm=\"x\""], none), (b, b, vec![]));
        assert_eq!(read(&[b"basic"], none), (b, b, vec![]));
        assert_eq!(read(&[b"Basicx, Bearer"], none), (br, br, vec![]));
        assert_eq!(read(&[b"X a=\"1\",\t Basic"], none), (b, b, vec![]));
        assert_eq!(read(&[b"X a=\"Basic\""], none), (none, none, vec![]));
        assert_eq!(read(&[b"Bearer, Basic"], b), (none, b | br, vec![b]));
        assert_eq!(read(&[b"Basic", b"Bearer"], b), (br, b | br, vec![b]));
    }

    /// A 401 with credentials picks Basic if offered and wanted, else is
    /// a problem; with none, nothing is picked. Only a 401 the request
    /// can still answer escapes fail-on-error.
    #[test]
    fn acts_on_a_401_as_c() {
        let offered = |m| Challenges {
            open: m,
            offered: m,
            refused: false,
        };
        let asked = AuthAsked {
            want: AuthMethods::ANY,
            credentials: true,
            user_or_password: true,
            ..AuthAsked::DEFAULT
        };
        let act = AuthAct::of(401, &offered(AuthMethods::BASIC), &asked);
        assert_eq!(
            (act.picked, act.reload, act.problem),
            (Some(AuthMethods::BASIC), true, false)
        );
        assert!(!act.fails(401, &asked));
        let act = AuthAct::of(401, &offered(AuthMethods::BEARER), &asked);
        assert_eq!(
            (act.picked, act.reload, act.problem),
            (Some(AuthMethods::NONE), false, true)
        );
        assert!(act.fails(401, &asked));
        let digest_only = AuthAsked {
            want: AuthMethods::DIGEST,
            ..asked
        };
        let act = AuthAct::of(401, &offered(AuthMethods::BASIC), &digest_only);
        assert!(act.problem && !act.reload);
        let empty = AuthAsked {
            user_or_password: false,
            ..asked
        };
        assert!(AuthAct::of(401, &offered(AuthMethods::BASIC), &empty).problem);
        let without = AuthAsked::DEFAULT;
        let act = AuthAct::of(401, &offered(AuthMethods::BASIC), &without);
        assert_eq!(act, AuthAct::default());
        assert!(act.fails(401, &without));
        assert!(AuthAct::of(200, &offered(AuthMethods::BASIC), &asked) == AuthAct::default());
    }

    /// The values the C tool sends, and RFC 4648's vectors.
    #[test]
    fn encodes_basic_as_c() {
        let basic = |u: &[u8], p: &[u8]| {
            let c = Credentials {
                user: u.to_vec(),
                password: p.to_vec(),
                source: Source::Options,
                trusted: Trusted::own_url(),
            };
            c.basic().unwrap().map(|b| String::from_utf8(b).unwrap())
        };
        assert_eq!(basic(b"", b"example").as_deref(), Some("OmV4YW1wbGU="));
        assert_eq!(basic(b"u", b"").as_deref(), Some("dTo="));
        assert_eq!(basic(b"a\x01b", b"x").as_deref(), Some("YQFiOng="));
        assert_eq!(basic(b"fo", b"").as_deref(), Some("Zm86"));
        assert_eq!(basic(b"foob", b"r").as_deref(), Some("Zm9vYjpy"));
        // `http://@host/` and `http://:@host/` send none.
        assert_eq!(basic(b"", b""), None);
    }
}
