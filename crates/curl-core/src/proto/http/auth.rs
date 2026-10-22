//! Authenticating HTTP requests (`lib/http.c`'s `Curl_http_output_auth`,
//! `Curl_http_input_auth` and `Curl_http_auth_act`): Basic, Bearer and
//! Digest, with the credentials the options or the URL carry
//! (`url_set_data_creds`), sent at once or once a server's challenge asks
//! for it; to the origin, and to an HTTP proxy a request goes through.

use curl_alloc::{OutOfMemory, TryVec as _, try_box};

use super::digest::{Digest, DigestError};
use super::request::Trusted;
use crate::conn::Peer;
use crate::error::UrlErrorKind;
use crate::netrc::Found;
use crate::options::{AuthMethods, Login, NetrcMode};
use crate::url::{GetOptions, Part, Url, decode_but_zero};

/// Authenticating over a handle's transfers, with the origin and with the
/// HTTP proxy (C's `state.authhost` and `state.authproxy`), and whether
/// either went wrong (`state.authproblem`), which stops both.
#[derive(Debug, Default)]
pub(crate) struct Auth {
    host: PeerAuth,
    proxy: PeerAuth,
    /// The credentials were refused, or none fit the challenge.
    problem: bool,
}

/// Which peer a request authenticates with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Side {
    Host,
    Proxy,
}

impl Auth {
    /// A transfer starts, wanting `host` of the origin and `proxy` of the
    /// proxy (`Curl_pretransfer`).
    pub(crate) fn start(&mut self, host: AuthMethods, proxy: AuthMethods) {
        self.problem = false;
        self.host.start(host);
        // A signature is never a proxy's: asked of one, it is as a method
        // not implemented (`output_auth_headers`).
        let signatures = AuthMethods::AWS_SIGV4 | AuthMethods::HTTPSIG;
        let proxy = if (proxy & signatures).is_empty() {
            proxy
        } else {
            (proxy & !signatures) | AuthMethods::OTHER
        };
        self.proxy.start(proxy);
    }

    /// Authenticating went wrong, and stops (`state.authproblem`).
    pub(crate) fn problem(&self) -> bool {
        self.problem
    }

    /// Whether the proxy offered methods not picked from, these
    /// challenges among them (`authproxy.avail`).
    pub(crate) fn proxy_offers(&self, challenges: &Challenges) -> bool {
        !challenges.open.unwrap_or(self.proxy.avail).is_empty()
    }

    pub(crate) fn side(&mut self, side: Side) -> &mut PeerAuth {
        match side {
            Side::Host => &mut self.host,
            Side::Proxy => &mut self.proxy,
        }
    }

    /// What a request asks of its response's challenges: with these
    /// credentials for the origin, and for the proxy, each kept with its
    /// peer.
    pub(crate) fn asked(
        &self,
        host: (Option<Secret<'_>>, &Peer),
        proxy: (Option<Secret<'_>>, &Peer),
        probe: bool,
        get_or_head: bool,
    ) -> AuthAsked {
        AuthAsked {
            host: self.host.asked(host.0, host.1),
            proxy: self.proxy.asked(proxy.0, proxy.1),
            probe,
            get_or_head,
            problem: self.problem,
        }
    }

    /// What a response offered, and what its challenges led to
    /// (`Curl_http_auth_act`): the origin's kept for `origin`, the
    /// proxy's for `proxy`.
    pub(crate) fn apply(
        &mut self,
        act: &AuthAct,
        offered: Offered,
        origin: &Peer,
        proxy: &Peer,
    ) -> Result<(), OutOfMemory> {
        self.problem = act.problem;
        self.host
            .apply(act.picked, act.done, offered.host, origin)?;
        self.proxy
            .apply(act.proxy_picked, false, offered.proxy, proxy)
    }
}

/// Authenticating with one peer, over a handle's transfers.
#[derive(Debug, Default)]
pub(crate) struct PeerAuth {
    /// The methods the transfer may use.
    want: AuthMethods,
    /// The method chosen. Kept from one transfer to the next, as the
    /// handle keeps it.
    picked: Picked,
    /// Authenticating is as far as it goes.
    done: bool,
    /// The last Digest challenge read (C's `state.digest`), in memory of
    /// its own: made only where a server asks for Digest.
    digest: Option<Box<DigestState>>,
    /// The methods offered and not yet picked from (`avail`): a response
    /// whose challenges are not acted on leaves them for the next, of
    /// this transfer or a later one.
    avail: AuthMethods,
}

/// The method chosen (C's `picked`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Picked {
    /// None yet: the wanted set stands in until a server asks.
    #[default]
    NotYet,
    /// The wanted set, before a server asks; the one method, after.
    Methods(AuthMethods),
    /// A server asked and nothing wanted fits (`CURLAUTH_PICKNONE`):
    /// nothing goes until the next transfer.
    Nothing,
}

impl Picked {
    fn methods(self) -> AuthMethods {
        match self {
            Picked::Methods(m) => m,
            Picked::NotYet | Picked::Nothing => AuthMethods::NONE,
        }
    }
}

/// A Digest challenge, kept for the origin that sent it and the
/// credentials it answers with (`digest_flush_stale`): asked of by any
/// other origin it is not there, and other credentials start it over.
#[derive(Debug)]
struct DigestState {
    origin: Peer,
    answered: Option<Answered>,
    digest: Digest,
}

/// The credentials a Digest challenge was answered with, to tell when
/// they change (`Curl_creds_same`).
#[derive(Debug)]
struct Answered {
    user: Vec<u8>,
    password: Vec<u8>,
    bearer: Vec<u8>,
}

/// What a request is, for its credentials to answer.
#[derive(Debug)]
pub(crate) struct AuthRequest<'r> {
    /// The peer authenticated with.
    pub(crate) origin: &'r Peer,
    /// The method as the request line names it.
    pub(crate) method: &'r [u8],
    /// The path and query, as the URL holds them.
    pub(crate) uri: &'r [u8],
    pub(crate) get_or_head: bool,
    /// What the application set for the first origin may go to this
    /// one (`Curl_auth_allowed_to_host`).
    pub(crate) trusted: Option<Trusted>,
}

/// What a request sends to authenticate.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Output {
    /// The method whose `Authorization` goes, and what follows its name.
    pub(crate) header: Option<(AuthMethods, Vec<u8>)>,
    /// The method in use, though it may send nothing yet, for the report
    /// (`info.httpauthpicked`).
    pub(crate) used: AuthMethods,
    /// The request goes without its body, a probe for a method that
    /// takes more than one (`req.authneg`).
    pub(crate) probe: bool,
}

/// Why a request's authentication could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutputError {
    OutOfMemory,
    /// No random bytes for Digest's client nonce.
    Random,
}

impl From<OutOfMemory> for OutputError {
    fn from(_: OutOfMemory) -> Self {
        OutputError::OutOfMemory
    }
}

impl PeerAuth {
    /// Authenticating is as far as it goes: a tunnel is up through the
    /// proxy (`H1_TUNNEL_ESTABLISHED`).
    pub(crate) fn finish(&mut self) {
        self.done = true;
    }

    /// A transfer starts, wanting `want`.
    fn start(&mut self, want: AuthMethods) {
        self.want = want;
        let kept = self.picked.methods() & want;
        self.picked = if kept.is_empty() {
            Picked::NotYet
        } else {
            Picked::Methods(kept)
        };
    }

    /// What `request`, with `credentials`, sends to authenticate with
    /// the peer (`Curl_http_output_auth`, `output_auth_headers`).
    /// `custom` says the application sends its own Authorization, which
    /// Basic and Bearer do not replace; Digest goes beside it, as C's
    /// does. `random` makes Digest's client nonce.
    pub(crate) fn output(
        &mut self,
        credentials: Option<Secret<'_>>,
        custom: bool,
        request: &AuthRequest<'_>,
        random: impl FnOnce(&mut [u8; 12]) -> Result<(), ()>,
    ) -> Result<Output, OutputError> {
        // A message signature signs with its own key, credentials or
        // not (`Curl_http_output_auth`).
        if credentials.is_none() && !self.want.contains(AuthMethods::HTTPSIG) {
            self.done = true;
            return Ok(Output {
                header: None,
                used: AuthMethods::NONE,
                probe: false,
            });
        }
        if !self.want.is_empty() && self.picked == Picked::NotYet {
            // Before a server asks: one method wanted is used at once.
            self.picked = Picked::Methods(self.want);
        }
        // Whether the method is in use, and what it sends.
        let (active, value) = match (self.picked.methods().single(), credentials) {
            (Some(AuthMethods::BASIC), credentials) => {
                self.done = true;
                let value = match credentials.filter(|_| !custom) {
                    Some(credentials) => credentials.basic()?,
                    None => None,
                };
                (value.is_some(), value)
            }
            (Some(AuthMethods::BEARER), credentials) => {
                self.done = true;
                let value = match credentials.filter(|c| !custom && c.has_bearer()) {
                    Some(credentials) => Some(copy(credentials.bearer)?),
                    None => None,
                };
                (value.is_some(), value)
            }
            // Signed where the request is made, and only for an origin
            // the application's settings may go to; never more than once.
            (Some(AuthMethods::HTTPSIG), _) => {
                self.done = true;
                (request.trusted.is_some(), None)
            }
            // Signed where the request is made, unless the application
            // sends its own Authorization; never more than once.
            (Some(AuthMethods::AWS_SIGV4), _) => {
                self.done = true;
                (true, None)
            }
            (Some(AuthMethods::DIGEST), Some(credentials)) => {
                // In use from the start; done once a challenge is answered.
                let value = self.answer_digest(credentials, request, random)?;
                self.done = value.is_some();
                (true, value)
            }
            _ => (false, None),
        };
        let picked = self.picked.methods();
        Ok(Output {
            header: value.map(|v| (picked, v)),
            used: if active { picked } else { AuthMethods::NONE },
            // A method that takes more than one request, not done, probes
            // without the body.
            probe: active && !self.done && !request.get_or_head,
        })
    }

    /// The `Authorization: Digest` value answering the challenge kept for
    /// `request`'s origin, if one with a nonce is (`Curl_output_digest`).
    fn answer_digest(
        &mut self,
        credentials: Secret<'_>,
        request: &AuthRequest<'_>,
        random: impl FnOnce(&mut [u8; 12]) -> Result<(), ()>,
    ) -> Result<Option<Vec<u8>>, OutputError> {
        let stale = self.digest.as_ref().is_some_and(|s| {
            s.origin != *request.origin
                || s.answered
                    .as_ref()
                    .is_some_and(|a| !credentials.answers_as(a))
        });
        if stale {
            self.digest = None;
        }
        let Some(state) = self.digest.as_mut() else {
            return Ok(None);
        };
        state.answered = Some(credentials.answered()?);
        if !state.digest.has_nonce() {
            return Ok(None);
        }
        let mut failed = false;
        let value = state.digest.response(
            credentials.user,
            credentials.password,
            request.method,
            request.uri,
            |bytes| failed = random(bytes).is_err(),
        )?;
        if failed {
            return Err(OutputError::Random);
        }
        Ok(Some(value))
    }

    /// What a request to `origin` asks of its response's challenges.
    fn asked(&self, credentials: Option<Secret<'_>>, origin: &Peer) -> PeerAsked {
        PeerAsked {
            want: self.want,
            picked: self.picked.methods(),
            credentials: credentials.is_some(),
            user_or_password: credentials.is_some_and(|c| c.has_user_or_password()),
            bearer: credentials.is_some_and(|c| c.has_bearer()),
            done: self.done,
            avail: self.avail,
            digest_nonce: self
                .digest
                .as_ref()
                .is_some_and(|s| s.origin == *origin && s.digest.has_nonce()),
        }
    }

    /// What a response from `origin` offered, the method it led to pick
    /// and whether authenticating is done. A Digest challenge read
    /// replaces the one kept, refused or not, as C's does
    /// (`Curl_input_digest`).
    fn apply(
        &mut self,
        picked: Option<AuthMethods>,
        done: bool,
        challenges: Challenges,
        origin: &Peer,
    ) -> Result<(), OutOfMemory> {
        if let Some(picked) = picked {
            self.picked = if picked.is_empty() {
                Picked::Nothing
            } else {
                Picked::Methods(picked)
            };
        }
        self.done |= done;
        // A pick takes from what was open, and leaves nothing open.
        self.avail = match picked {
            Some(_) => AuthMethods::NONE,
            None => challenges.open.unwrap_or(self.avail),
        };
        if let Some(digest) = challenges.digest {
            self.digest = Some(try_box(DigestState {
                origin: origin.try_clone()?,
                answered: None,
                digest,
            })?);
        }
        Ok(())
    }
}

/// What a request knows of authenticating, for its response to act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuthAsked {
    pub(crate) host: PeerAsked,
    pub(crate) proxy: PeerAsked,
    /// The request went without its body (`req.authneg`).
    probe: bool,
    get_or_head: bool,
    problem: bool,
}

/// What a request knows of authenticating with one peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PeerAsked {
    want: AuthMethods,
    picked: AuthMethods,
    /// The request has credentials, empty ones too.
    credentials: bool,
    user_or_password: bool,
    bearer: bool,
    done: bool,
    /// The methods offered before and not picked from.
    avail: AuthMethods,
    /// A Digest nonce from the peer was answered already.
    digest_nonce: bool,
}

impl PeerAsked {
    /// Without credentials, wanting nothing.
    pub(crate) const DEFAULT: PeerAsked = PeerAsked {
        want: AuthMethods::NONE,
        picked: AuthMethods::NONE,
        credentials: false,
        user_or_password: false,
        bearer: false,
        done: false,
        avail: AuthMethods::NONE,
        digest_nonce: false,
    };
}

impl AuthAsked {
    /// A request without credentials, wanting nothing.
    pub(crate) const DEFAULT: AuthAsked = AuthAsked {
        host: PeerAsked::DEFAULT,
        proxy: PeerAsked::DEFAULT,
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

/// What a response's challenges offered: a 401's the origin's, a 407's
/// the proxy's.
#[derive(Debug, Default)]
pub(crate) struct Offered {
    pub(crate) host: Challenges,
    pub(crate) proxy: Challenges,
}

/// What the challenges of a response offered (`Curl_http_input_auth`).
#[derive(Debug, Default)]
pub(crate) struct Challenges {
    /// The methods offered and still open, those left from before among
    /// them: a refusal closes them all (C's `avail`). None until a
    /// challenge is read.
    open: Option<AuthMethods>,
    /// Every method offered, for the report (`info.httpauthavail`).
    pub(crate) offered: AuthMethods,
    /// The credentials were refused, or a challenge could not be read.
    refused: bool,
    /// The Digest challenge, read whether or not Digest is wanted.
    digest: Option<Digest>,
}

/// What C says as it reads one challenge line, in order (`infof`): at
/// most `HEARD` notes, any more left unsaid, so that a line cannot make
/// the head's notes grow without bound.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Heard([Option<HeardNote>; HEARD]);

const HEARD: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeardNote {
    /// "<method> authentication problem, ignoring."
    Problem(AuthMethods),
    /// A second Digest challenge in one response.
    DuplicateDigest,
}

impl Heard {
    fn push(&mut self, note: HeardNote) {
        if let Some(free) = self.0.iter_mut().find(|n| n.is_none()) {
            *free = Some(note);
        }
    }

    pub(crate) fn notes(self) -> impl Iterator<Item = HeardNote> {
        self.0.into_iter().flatten()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0[0].is_none()
    }
}

impl Challenges {
    /// A `WWW-Authenticate:` or `Proxy-Authenticate:` value, its methods
    /// one after another, separated by commas; what C says of it.
    pub(crate) fn read(
        &mut self,
        mut value: &[u8],
        asked: &PeerAsked,
    ) -> Result<Heard, OutOfMemory> {
        let mut heard = Heard::default();
        let mut open = self.open(asked);
        while !value.is_empty() {
            if names(value, AuthMethods::DIGEST.name()) {
                self.digest_challenge(value, asked, &mut open, &mut heard)?;
            }
            for method in [AuthMethods::BASIC, AuthMethods::BEARER] {
                if names(value, method.name()) {
                    self.offered = self.offered | method;
                    open = open | method;
                    if asked.picked == method {
                        // Asked for and offered again anyway: refused.
                        open = AuthMethods::NONE;
                        self.refused = true;
                        heard.push(HeardNote::Problem(method));
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
        self.open = Some(open);
        Ok(heard)
    }

    /// The credentials were refused, or a challenge could not be read.
    pub(crate) fn refused(&self) -> bool {
        self.refused
    }

    /// The methods open: those left from before, until a challenge is
    /// read.
    fn open(&self, asked: &PeerAsked) -> AuthMethods {
        self.open.unwrap_or(asked.avail)
    }

    /// `Digest` and what follows it to the line's end (`auth_digest`,
    /// `Curl_input_digest`): read only if Digest is not open already,
    /// though it was offered before this response, as C's `avail` has it.
    fn digest_challenge(
        &mut self,
        value: &[u8],
        asked: &PeerAsked,
        open: &mut AuthMethods,
        heard: &mut Heard,
    ) -> Result<(), OutOfMemory> {
        self.offered = self.offered | AuthMethods::DIGEST;
        if open.contains(AuthMethods::DIGEST) {
            heard.push(HeardNote::DuplicateDigest);
            return Ok(());
        }
        *open = *open | AuthMethods::DIGEST;
        let rest = &value[AuthMethods::DIGEST.name().len()..];
        let (digest, read) = match rest.first() {
            // The blanks are passed as those between pairs are.
            Some(b' ' | b'\t') => Digest::decode(rest, asked.digest_nonce),
            // Nothing after the name, or a comma: no challenge.
            _ => (Digest::default(), Err(DigestError::Bad)),
        };
        match read {
            Ok(()) => {}
            Err(DigestError::OutOfMemory) => return Err(OutOfMemory),
            Err(DigestError::Bad) => {
                self.refused = true;
                heard.push(HeardNote::Problem(AuthMethods::DIGEST));
            }
        }
        self.digest = Some(digest);
        Ok(())
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
    /// The method chosen for the origin, none if none fits, when one was
    /// chosen.
    pub(crate) picked: Option<AuthMethods>,
    /// The method chosen for the proxy, as `picked`.
    pub(crate) proxy_picked: Option<AuthMethods>,
    pub(crate) problem: bool,
    /// The request is made again, its body not delivered.
    pub(crate) reload: bool,
    pub(crate) done: bool,
}

impl AuthAct {
    /// What a response with `code` offering `offered` leads to, for a
    /// request that asked `asked` (`Curl_http_auth_act`, `pickoneauth`):
    /// a 401 picks a method for the origin, a 407 for the proxy, and a
    /// probe let through for both.
    pub(crate) fn of(code: u16, offered: &Offered, asked: &AuthAsked) -> AuthAct {
        let mut act = AuthAct {
            problem: asked.problem || offered.host.refused || offered.proxy.refused,
            ..AuthAct::default()
        };
        if act.problem {
            return act;
        }
        let probed = asked.probe && code < 300;
        if asked.host.credentials && (code == 401 || probed) {
            let picked = pick(&offered.host, &asked.host, asked.host.bearer);
            act.picked = Some(picked);
            act.problem |= picked.is_empty();
        }
        if asked.proxy.credentials && (code == 407 || probed) {
            // Never Bearer, whatever was offered.
            let picked = pick(&offered.proxy, &asked.proxy, false);
            act.proxy_picked = Some(picked);
            act.problem |= picked.is_empty();
        }
        act.reload = [act.picked, act.proxy_picked]
            .iter()
            .any(|p| p.is_some_and(|p| !p.is_empty()));
        // A probe let through without a method picked is made again
        // with its body, authenticating with the origin as far as it
        // goes.
        if !act.reload && code < 300 && !asked.host.done && asked.probe && !asked.get_or_head {
            act.reload = true;
            act.done = true;
        }
        act
    }

    /// Whether a 401 or 407 is an error to fail on, as other codes of 400
    /// or more are (`http_should_fail`): one asking for credentials the
    /// request has for that peer, not yet refused, is not.
    pub(crate) fn fails(&self, code: u16, asked: &AuthAsked) -> bool {
        match code {
            401 => !asked.host.credentials || self.problem,
            407 => !asked.proxy.credentials || self.problem,
            _ => true,
        }
    }
}

/// The method `challenges` lead a request asking `asked` to pick, in C's
/// order of preference, Bearer only if `bearer`; none if none fits.
fn pick(challenges: &Challenges, asked: &PeerAsked, bearer: bool) -> AuthMethods {
    let mut open = challenges.open(asked) & asked.want;
    if !bearer {
        open = open & !AuthMethods::BEARER;
    }
    if open.contains(AuthMethods::BEARER) {
        AuthMethods::BEARER
    } else if open.contains(AuthMethods::DIGEST) && asked.user_or_password {
        AuthMethods::DIGEST
    } else if open.contains(AuthMethods::BASIC) && asked.user_or_password {
        AuthMethods::BASIC
    } else {
        AuthMethods::NONE
    }
}

/// The user and password a request authenticates with, decoded (C's
/// `struct Curl_creds`), and the leave to send them to its origin.
#[derive(Debug)]
pub(crate) struct Credentials {
    user: Vec<u8>,
    password: Vec<u8>,
    /// An OAuth 2.0 token, empty for none.
    bearer: Vec<u8>,
    source: Source,
    trusted: Trusted,
}

/// Where credentials came from (`CREDS_*`): the last that gave any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    Options,
    Url,
    Netrc,
}

/// Whether a `.netrc` file is read for a request, and for which user.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NetrcLookup<'c> {
    No,
    /// For any user, or the one named.
    For(Option<&'c [u8]>),
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
        let (mut user, mut password, mut bearer) = (None, None, Vec::new());
        if let Some(trusted) = trusted {
            user = login.user.as_deref().map(copy).transpose()?;
            password = login.password.as_deref().map(copy).transpose()?;
            bearer = login
                .bearer
                .as_deref()
                .map(copy)
                .transpose()?
                .unwrap_or_default();
            if let Some(user) = user.take_if(|u| !u.is_empty()) {
                return Ok(Some(Credentials {
                    user,
                    password: password.unwrap_or_default(),
                    bearer,
                    source: Source::Options,
                    trusted,
                }));
            }
        }
        if let Some((url_user, url_password)) = Self::of_url(url)? {
            user = url_user.or(user);
            password = url_password.or(password);
        } else if user.is_none() && password.is_none() && bearer.is_empty() {
            return Ok(None);
        }
        // What the login left blank merged with the URL is the URL's,
        // even where the URL had nothing (`Curl_creds_merge`).
        Ok(Some(Credentials {
            user: user.unwrap_or_default(),
            password: password.unwrap_or_default(),
            bearer,
            source: Source::Url,
            // A login gets this far only trusted; the URL's own always.
            trusted: trusted.unwrap_or_else(Trusted::own_url),
        }))
    }

    /// Whether `credentials` leave a `.netrc` file to read in `mode`, and
    /// for which user (`url_set_data_creds_netrc`): never over the
    /// options', and over the URL's only to complete them, or to replace
    /// the password where the file is required.
    pub(crate) fn netrc_lookup(
        credentials: Option<&Credentials>,
        mode: NetrcMode,
    ) -> NetrcLookup<'_> {
        if mode == NetrcMode::Ignored {
            return NetrcLookup::No;
        }
        let Some(c) = credentials else {
            return NetrcLookup::For(None);
        };
        match c.source {
            Source::Options => NetrcLookup::No,
            Source::Url
                if mode == NetrcMode::Required || c.user.is_empty() || c.password.is_empty() =>
            {
                NetrcLookup::For(Some(&c.user))
            }
            Source::Url => NetrcLookup::No,
            Source::Netrc => NetrcLookup::For(None),
        }
    }

    /// `credentials` with a `.netrc` entry's user and password in place
    /// of theirs, a token kept (`Curl_creds_merge`). The entry is for the
    /// request's own host, so goes there wherever the transfer started.
    pub(crate) fn with_netrc(credentials: Option<Credentials>, found: Found) -> Credentials {
        Credentials {
            user: found.user,
            password: found.password,
            bearer: credentials.map(|c| c.bearer).unwrap_or_default(),
            source: Source::Netrc,
            trusted: Trusted::own_url(),
        }
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

    /// What these authenticate with.
    pub(crate) fn secret(&self) -> Secret<'_> {
        Secret {
            user: &self.user,
            password: &self.password,
            bearer: &self.bearer,
        }
    }

    /// The leave to send these to the request's origin.
    pub(crate) fn trusted(&self) -> Trusted {
        self.trusted
    }
}

/// What a request authenticates with to one peer: a user and a password,
/// and a token, each empty for none.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Secret<'a> {
    user: &'a [u8],
    password: &'a [u8],
    bearer: &'a [u8],
}

impl<'a> Secret<'a> {
    /// A user and a password, without a token: a proxy takes none.
    pub(crate) fn new(user: &'a [u8], password: &'a [u8]) -> Secret<'a> {
        Secret {
            user,
            password,
            bearer: &[],
        }
    }

    pub(crate) fn user(&self) -> &'a [u8] {
        self.user
    }

    pub(crate) fn password(&self) -> &'a [u8] {
        self.password
    }

    /// A user or a password, not both empty (`Curl_creds_has_user_or_pass`).
    fn has_user_or_password(&self) -> bool {
        !self.user.is_empty() || !self.password.is_empty()
    }

    fn has_bearer(&self) -> bool {
        !self.bearer.is_empty()
    }

    /// These, kept to tell whether a Digest challenge answered with them
    /// is answered with others.
    fn answered(&self) -> Result<Answered, OutOfMemory> {
        Ok(Answered {
            user: copy(self.user)?,
            password: copy(self.password)?,
            bearer: copy(self.bearer)?,
        })
    }

    /// Whether these are those `answered` kept (`Curl_creds_same`, whose
    /// comparisons take the same time whatever the bytes).
    fn answers_as(&self, answered: &Answered) -> bool {
        same_secret(self.user, &answered.user)
            & same_secret(self.password, &answered.password)
            & same_secret(self.bearer, &answered.bearer)
    }

    /// `user:password` in base64, what `Authorization: Basic` carries;
    /// nothing when both are empty (`Curl_creds_has_user_or_pass`).
    fn basic(&self) -> Result<Option<Vec<u8>>, OutOfMemory> {
        if self.user.is_empty() && self.password.is_empty() {
            return Ok(None);
        }
        let len = self.user.len() + 1 + self.password.len();
        let mut out = Vec::new();
        out.try_reserve_exact(len.div_ceil(3) * 4)
            .map_err(|_| OutOfMemory)?;
        let bytes = self.user.iter().chain(b":").chain(self.password).copied();
        base64(bytes, len, &mut out)?;
        Ok(Some(out))
    }
}

fn copy(bytes: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut v = Vec::new();
    v.try_extend_from_slice(bytes).map_err(|_| OutOfMemory)?;
    Ok(v)
}

/// Whether two secrets are the same, their bytes all compared whatever
/// the first difference (`Curl_timestrcmp`).
fn same_secret(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |d, (x, y)| d | (x ^ y)) == 0
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `len` bytes from `bytes` in base64 with padding, into `out`.
pub(crate) fn base64(
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

/// Any request's view of authenticating, for the properties of what
/// reads a response.
#[cfg(test)]
pub(crate) mod arbitrary {
    use proptest::prelude::*;

    use super::{AuthAsked, PeerAsked};
    use crate::options::AuthMethods;

    /// Any set of the methods, `ONLY` and `OTHER` among them.
    pub(crate) fn methods() -> impl Strategy<Value = AuthMethods> {
        any::<u8>().prop_map(|bits| {
            [
                AuthMethods::BASIC,
                AuthMethods::DIGEST,
                AuthMethods::BEARER,
                AuthMethods::OTHER,
                AuthMethods::ONLY,
            ]
            .into_iter()
            .enumerate()
            .filter(|&(i, _)| bits & (1 << i) != 0)
            .fold(AuthMethods::NONE, |set, (_, m)| set | m)
        })
    }

    pub(crate) fn peer_asked() -> impl Strategy<Value = PeerAsked> {
        (methods(), methods(), methods(), any::<[bool; 5]>()).prop_map(
            |(want, picked, avail, [credentials, user_or_password, bearer, done, digest_nonce])| {
                PeerAsked {
                    want,
                    picked,
                    credentials,
                    user_or_password: credentials && user_or_password,
                    bearer: credentials && bearer,
                    done,
                    avail,
                    digest_nonce,
                }
            },
        )
    }

    /// A request sent without its body to probe for a challenge, which
    /// a response under 300 has made again (`req.authneg`).
    pub(crate) const PROBE: AuthAsked = AuthAsked {
        probe: true,
        get_or_head: false,
        ..AuthAsked::DEFAULT
    };

    /// A request with a user and password for Basic, which a 401
    /// offering it has made again.
    pub(crate) const BASIC: AuthAsked = AuthAsked {
        host: PeerAsked {
            want: AuthMethods::BASIC,
            credentials: true,
            user_or_password: true,
            ..PeerAsked::DEFAULT
        },
        ..AuthAsked::DEFAULT
    };

    pub(crate) fn auth_asked() -> impl Strategy<Value = AuthAsked> {
        (peer_asked(), peer_asked(), any::<[bool; 3]>()).prop_map(
            |(host, proxy, [probe, get_or_head, problem])| AuthAsked {
                host,
                proxy,
                probe,
                get_or_head,
                problem,
            },
        )
    }
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
            bearer: None,
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

    /// A token goes where the login would, kept through the URL's
    /// credentials; alone it still makes credentials.
    #[test]
    fn composes_a_token_with_the_rest() {
        let token = Login {
            bearer: Some(b"t".to_vec()),
            ..Login::default()
        };
        let bearer = |trusted: bool, url: &str| {
            let url = Url::parse(url.as_bytes(), ParseOptions::NONE).unwrap();
            let trusted = trusted.then(Trusted::own_url);
            Credentials::for_request(&token, trusted, &url)
                .unwrap()
                .map(|c| (c.user, c.bearer))
        };
        assert_eq!(bearer(true, "http://h/"), Some((vec![], b"t".to_vec())));
        assert_eq!(
            bearer(true, "http://u@h/"),
            Some((b"u".to_vec(), b"t".to_vec()))
        );
        assert_eq!(bearer(false, "http://h/"), None);
        assert_eq!(bearer(false, "http://u@h/"), Some((b"u".to_vec(), vec![])));
    }

    /// As C's `url_set_data_creds_netrc` decides: never over the
    /// options', over the URL's to complete them or, if required, to
    /// replace the password, naming the URL's user.
    #[test]
    fn looks_in_netrc_as_c() {
        let creds = |user: &[u8], password: &[u8], source| Credentials {
            user: user.to_vec(),
            password: password.to_vec(),
            bearer: Vec::new(),
            source,
            trusted: Trusted::own_url(),
        };
        let (opt, req, ign) = (NetrcMode::Optional, NetrcMode::Required, NetrcMode::Ignored);
        fn look(c: Option<&Credentials>, mode: NetrcMode) -> NetrcLookup<'_> {
            Credentials::netrc_lookup(c, mode)
        }
        assert_eq!(look(None, ign), NetrcLookup::No);
        assert_eq!(look(None, opt), NetrcLookup::For(None));
        let options = creds(b"u", b"", Source::Options);
        assert_eq!(look(Some(&options), req), NetrcLookup::No);
        let whole = creds(b"u", b"p", Source::Url);
        assert_eq!(look(Some(&whole), opt), NetrcLookup::No);
        assert_eq!(look(Some(&whole), req), NetrcLookup::For(Some(b"u")));
        let user_only = creds(b"u", b"", Source::Url);
        assert_eq!(look(Some(&user_only), opt), NetrcLookup::For(Some(b"u")));
        let password_only = creds(b"", b"p", Source::Url);
        assert_eq!(look(Some(&password_only), opt), NetrcLookup::For(Some(b"")));
    }

    /// Methods are read at the start of each comma-separated part, whole
    /// words only, in any case; the one used offered again is refused,
    /// and closes what was open.
    #[test]
    fn reads_challenges_as_c() {
        let read = |values: &[&[u8]], picked| {
            let asked = PeerAsked {
                picked,
                ..PeerAsked::DEFAULT
            };
            let mut c = Challenges::default();
            let mut refused = Vec::new();
            for v in values {
                for note in c.read(v, &asked).unwrap().notes() {
                    match note {
                        HeardNote::Problem(m) => refused.push(m),
                        HeardNote::DuplicateDigest => unreachable!("no Digest here"),
                    }
                }
            }
            (c.open.unwrap(), c.offered, refused)
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

    /// A Digest challenge is read whole, the first in a response only,
    /// and kept even where it is refused; one without a blank after the
    /// name, or a new nonce not called stale, is a problem.
    #[test]
    fn reads_digest_challenges_as_c() {
        let read = |values: &[&[u8]], had_nonce| {
            let asked = PeerAsked {
                digest_nonce: had_nonce,
                ..PeerAsked::DEFAULT
            };
            let mut c = Challenges::default();
            let mut notes = Vec::new();
            for v in values {
                notes.extend(c.read(v, &asked).unwrap().notes());
            }
            (c, notes)
        };
        let d = AuthMethods::DIGEST;
        let (c, notes) = read(&[b"Digest realm=\"r\", nonce=\"1\", Basic"], false);
        assert_eq!(
            (c.open.unwrap(), c.offered, c.refused),
            (d | AuthMethods::BASIC, d | AuthMethods::BASIC, false)
        );
        assert!(notes.is_empty() && c.digest.as_ref().is_some_and(Digest::has_nonce));
        let (c, notes) = read(&[b"Digest nonce=\"1\"", b"Digest nonce=\"2\""], false);
        assert_eq!(notes, [HeardNote::DuplicateDigest]);
        assert!(!c.refused);
        let (c, notes) = read(&[b"Digest\tnonce=\"1\""], false);
        assert!(notes.is_empty() && !c.refused(), "a tab before the pairs");
        assert!(
            Challenges::default()
                .read(b"Digest nonce=\"1\"", &PeerAsked::DEFAULT)
                .unwrap()
                .is_empty()
        );
        for bad in [&b"Digest"[..], b"Digest,nonce=1", b"Digest realm=\"r\""] {
            let (c, notes) = read(&[bad], false);
            assert_eq!(
                (c.refused(), notes),
                (true, vec![HeardNote::Problem(d)]),
                "{bad:?}"
            );
            assert!(c.digest.is_some(), "kept anyway");
        }
        let (c, _) = read(&[b"Digest nonce=\"2\""], true);
        assert!(c.refused, "a nonce answered, and a new one not stale");
        let (c, _) = read(&[b"Digest nonce=\"2\", stale=true"], true);
        assert!(!c.refused);
        // However many a line has, what it says is bounded.
        let mut many = b"Digest nonce=1".to_vec();
        for _ in 0..20 {
            many.extend_from_slice(b", Digest");
        }
        let (_, notes) = read(&[&many], false);
        assert_eq!(notes.len(), HEARD);
        // Left open by an earlier response not acted on, a Digest
        // challenge is not read again (test 2027).
        let leftover = PeerAsked {
            avail: d,
            ..PeerAsked::DEFAULT
        };
        let mut c = Challenges::default();
        let notes: Vec<_> = c
            .read(b"Digest nonce=\"9\"", &leftover)
            .unwrap()
            .notes()
            .collect();
        assert_eq!(notes, [HeardNote::DuplicateDigest]);
        assert!(c.digest.is_none());
        // A refusal closes it, and the next is read.
        let basic = PeerAsked {
            picked: AuthMethods::BASIC,
            ..leftover
        };
        let mut c = Challenges::default();
        let notes: Vec<_> = c
            .read(b"Basic, Digest nonce=\"9\"", &basic)
            .unwrap()
            .notes()
            .collect();
        assert_eq!(notes, [HeardNote::Problem(AuthMethods::BASIC)]);
        assert!(c.digest.is_some());
    }

    fn offered(m: AuthMethods) -> Challenges {
        Challenges {
            open: Some(m),
            offered: m,
            refused: false,
            digest: None,
        }
    }

    /// What a response offering the origin `host` leads to.
    fn host_act(code: u16, host: Challenges, asked: &PeerAsked) -> AuthAct {
        let offered = Offered {
            host,
            proxy: Challenges::default(),
        };
        let asked = AuthAsked {
            host: *asked,
            ..AuthAsked::DEFAULT
        };
        AuthAct::of(code, &offered, &asked)
    }

    fn of_host(asked: &PeerAsked) -> AuthAsked {
        AuthAsked {
            host: *asked,
            ..AuthAsked::DEFAULT
        }
    }

    /// A 401 with credentials picks Basic if offered and wanted, else is
    /// a problem; with none, nothing is picked. Only a 401 the request
    /// can still answer escapes fail-on-error.
    #[test]
    fn acts_on_a_401_as_c() {
        let asked = PeerAsked {
            want: AuthMethods::ANY,
            credentials: true,
            user_or_password: true,
            ..PeerAsked::DEFAULT
        };
        let act = host_act(401, offered(AuthMethods::BASIC), &asked);
        assert_eq!(
            (act.picked, act.reload, act.problem),
            (Some(AuthMethods::BASIC), true, false)
        );
        assert!(!act.fails(401, &of_host(&asked)));
        let act = host_act(401, offered(AuthMethods::BEARER), &asked);
        assert_eq!(
            (act.picked, act.reload, act.problem),
            (Some(AuthMethods::NONE), false, true)
        );
        assert!(act.fails(401, &of_host(&asked)));
        let digest_only = PeerAsked {
            want: AuthMethods::DIGEST,
            ..asked
        };
        let act = host_act(401, offered(AuthMethods::BASIC), &digest_only);
        assert!(act.problem && !act.reload);
        let both = || offered(AuthMethods::BASIC | AuthMethods::BEARER);
        let act = host_act(401, both(), &asked);
        assert_eq!(act.picked, Some(AuthMethods::BASIC), "no token: not Bearer");
        let token = PeerAsked {
            bearer: true,
            ..asked
        };
        let act = host_act(401, both(), &token);
        assert_eq!(act.picked, Some(AuthMethods::BEARER), "Bearer before Basic");
        let empty = PeerAsked {
            user_or_password: false,
            ..asked
        };
        assert!(host_act(401, offered(AuthMethods::BASIC), &empty).problem);
        let without = PeerAsked::DEFAULT;
        let act = host_act(401, offered(AuthMethods::BASIC), &without);
        assert_eq!(act, AuthAct::default());
        assert!(act.fails(401, &of_host(&without)));
        assert!(host_act(200, offered(AuthMethods::BASIC), &asked) == AuthAct::default());
        // Digest after Bearer, before Basic, and only with a user or a
        // password.
        let all = || offered(AuthMethods::BASIC | AuthMethods::DIGEST | AuthMethods::BEARER);
        assert_eq!(
            host_act(401, all(), &asked).picked,
            Some(AuthMethods::DIGEST)
        );
        assert_eq!(
            host_act(401, all(), &token).picked,
            Some(AuthMethods::BEARER)
        );
        assert!(host_act(401, offered(AuthMethods::DIGEST), &empty).problem);
        // A 401 with no challenge picks from what was left open.
        let leftover = PeerAsked {
            avail: AuthMethods::DIGEST,
            ..asked
        };
        let act = host_act(401, Challenges::default(), &leftover);
        assert_eq!(act.picked, Some(AuthMethods::DIGEST));
    }

    /// A 407 picks for the proxy as a 401 does for the origin, never
    /// Bearer; a 401 leaves the proxy alone, and a problem with either
    /// stops both (`state.authproblem`).
    #[test]
    fn acts_on_a_407_as_c() {
        let creds = PeerAsked {
            want: AuthMethods::ANY,
            credentials: true,
            user_or_password: true,
            bearer: true,
            ..PeerAsked::DEFAULT
        };
        let asked = AuthAsked {
            host: creds,
            proxy: creds,
            ..AuthAsked::DEFAULT
        };
        let of = |code, host, proxy| AuthAct::of(code, &Offered { host, proxy }, &asked);
        let both = || offered(AuthMethods::BASIC | AuthMethods::BEARER);
        let act = of(407, Challenges::default(), both());
        assert_eq!(
            (act.picked, act.proxy_picked, act.reload, act.problem),
            (None, Some(AuthMethods::BASIC), true, false)
        );
        assert!(!act.fails(407, &asked));
        let act = of(401, both(), both());
        assert_eq!(
            (act.picked, act.proxy_picked),
            (Some(AuthMethods::BEARER), None)
        );
        let act = of(407, Challenges::default(), offered(AuthMethods::BEARER));
        assert_eq!(
            (act.proxy_picked, act.reload),
            (Some(AuthMethods::NONE), false)
        );
        assert!(act.problem && act.fails(407, &asked));
        let refused = Challenges {
            refused: true,
            ..offered(AuthMethods::BASIC)
        };
        let act = of(401, both(), refused);
        assert_eq!(
            (act.picked, act.problem),
            (None, true),
            "the proxy's stops the host's"
        );
        let without = AuthAsked {
            proxy: PeerAsked::DEFAULT,
            ..asked
        };
        let act = AuthAct::of(407, &Offered::default(), &without);
        assert!(act.fails(407, &without) && !act.fails(407, &asked));
    }

    /// A probe a server lets through unasked is made again with its
    /// body, done, though no method was picked (test 175); one asked to
    /// authenticate picks as a 401 does.
    #[test]
    fn acts_on_a_probe_as_c() {
        let creds = PeerAsked {
            want: AuthMethods::DIGEST,
            credentials: true,
            user_or_password: true,
            ..PeerAsked::DEFAULT
        };
        let probe = AuthAsked {
            host: creds,
            probe: true,
            get_or_head: false,
            ..AuthAsked::DEFAULT
        };
        let of = |host, asked: &AuthAsked| {
            let offered = Offered {
                host,
                proxy: Challenges::default(),
            };
            AuthAct::of(200, &offered, asked)
        };
        let redirect = AuthAct::of(300, &Offered::default(), &probe);
        assert_eq!(
            redirect,
            AuthAct::default(),
            "only a 2xx lets a probe through"
        );
        let act = of(Challenges::default(), &probe);
        assert_eq!(
            (act.picked, act.reload, act.done, act.problem),
            (Some(AuthMethods::NONE), true, true, true)
        );
        let get = AuthAsked {
            get_or_head: true,
            ..probe
        };
        assert!(!of(Challenges::default(), &get).reload);
        let done = AuthAsked {
            host: PeerAsked {
                done: true,
                ..creds
            },
            ..probe
        };
        assert!(!of(Challenges::default(), &done).reload);
        let digest = Challenges {
            open: Some(AuthMethods::DIGEST),
            offered: AuthMethods::DIGEST,
            ..Challenges::default()
        };
        let act = AuthAct::of(
            401,
            &Offered {
                host: digest,
                proxy: Challenges::default(),
            },
            &probe,
        );
        assert_eq!(
            (act.picked, act.reload, act.done),
            (Some(AuthMethods::DIGEST), true, false)
        );
    }

    /// A Digest challenge answers only the origin that sent it, and only
    /// with the credentials it was first answered with; a response not
    /// acted on leaves what it offered open for the next (`avail`).
    #[test]
    fn keeps_digest_for_its_origin_and_credentials() {
        let peer = |host: &[u8]| Peer::new(crate::proto::HTTP, host.to_vec(), 80, None);
        let creds = |password: &[u8]| Credentials {
            user: b"u".to_vec(),
            password: password.to_vec(),
            bearer: Vec::new(),
            source: Source::Options,
            trusted: Trusted::own_url(),
        };
        let read = |auth: &mut PeerAuth| {
            let (digest, read) = Digest::decode(b"realm=\"r\", nonce=\"n\"", false);
            read.unwrap();
            let challenges = Challenges {
                open: Some(AuthMethods::DIGEST),
                offered: AuthMethods::DIGEST,
                refused: false,
                digest: Some(digest),
            };
            auth.apply(None, false, challenges, &peer(b"a")).unwrap();
        };
        let answers = |auth: &mut PeerAuth, at: &Peer, c: &Credentials| {
            let request = AuthRequest {
                origin: at,
                method: b"GET",
                uri: b"/",
                get_or_head: true,
                trusted: Some(Trusted::own_url()),
            };
            let out = auth
                .output(Some(c.secret()), false, &request, |_| Ok(()))
                .unwrap();
            out.header.is_some()
        };
        let (a, b, right) = (peer(b"A"), peer(b"b"), creds(b"p"));
        let mut auth = PeerAuth::default();
        auth.start(AuthMethods::DIGEST);
        read(&mut auth);
        assert_eq!(auth.asked(None, &a).avail, AuthMethods::DIGEST);
        assert!(auth.asked(None, &a).digest_nonce);
        assert!(!auth.asked(None, &b).digest_nonce);
        assert!(
            answers(&mut auth, &a, &right),
            "its own origin, in any case"
        );
        assert!(answers(&mut auth, &a, &right), "and again");
        assert!(!answers(&mut auth, &a, &creds(b"q")), "other credentials");
        assert!(!answers(&mut auth, &a, &right), "start it over");
        read(&mut auth);
        assert!(!answers(&mut auth, &b, &right), "another origin");
        assert!(!answers(&mut auth, &a, &right), "starts it over too");
        // Two differences in the bytes do not cancel out.
        read(&mut auth);
        assert!(answers(&mut auth, &a, &creds(b"ab")));
        assert!(!answers(&mut auth, &a, &creds(b"ba")), "other credentials");
        // A challenge refused for want of a nonce is kept, and answers
        // nothing.
        let (digest, refused) = Digest::decode(b"realm=\"r\"", false);
        assert!(refused.is_err());
        let challenges = Challenges {
            open: Some(AuthMethods::DIGEST),
            offered: AuthMethods::DIGEST,
            refused: true,
            digest: Some(digest),
        };
        auth.apply(None, false, challenges, &a).unwrap();
        assert!(!auth.asked(None, &a).digest_nonce);
        assert!(!answers(&mut auth, &a, &right), "no nonce to answer");
        // A pick leaves nothing open.
        let a_again = peer(b"a");
        auth.apply(
            Some(AuthMethods::DIGEST),
            false,
            Challenges::default(),
            &a_again,
        )
        .unwrap();
        assert_eq!(auth.asked(None, &a).avail, AuthMethods::NONE);
    }

    /// The handle's state as transfers read it: a problem acted on, until
    /// the next transfer; the proxy's methods left open; a side finished,
    /// or done by a response.
    #[test]
    fn keeps_the_handle_s_state() {
        let peer = Peer::new(crate::proto::HTTP, b"h".to_vec(), 80, None);
        let mut auth = Auth::default();
        auth.start(AuthMethods::ANY, AuthMethods::ANY);
        assert!(!auth.problem());
        let problem = AuthAct {
            problem: true,
            ..AuthAct::default()
        };
        auth.apply(&problem, Offered::default(), &peer, &peer)
            .unwrap();
        assert!(auth.problem());
        auth.start(AuthMethods::ANY, AuthMethods::ANY);
        assert!(!auth.problem(), "until the next transfer");
        assert!(!auth.proxy_offers(&Challenges::default()));
        assert!(auth.proxy_offers(&offered(AuthMethods::BASIC)));
        let open = Offered {
            host: Challenges::default(),
            proxy: offered(AuthMethods::BASIC),
        };
        auth.apply(&AuthAct::default(), open, &peer, &peer).unwrap();
        assert!(auth.proxy_offers(&Challenges::default()), "left open");
        assert!(
            !auth.proxy_offers(&offered(AuthMethods::NONE)),
            "a refusal closes them"
        );
        let asked = |auth: &Auth| auth.asked((None, &peer), (None, &peer), false, true);
        assert!(!asked(&auth).host.done && !asked(&auth).proxy.done);
        auth.side(Side::Proxy).finish();
        assert!(asked(&auth).proxy.done && !asked(&auth).host.done);
        let done = AuthAct {
            done: true,
            ..AuthAct::default()
        };
        auth.apply(&done, Offered::default(), &peer, &peer).unwrap();
        assert!(asked(&auth).host.done);
    }

    /// Basic and Digest only with a user or a password, Bearer only with
    /// a token; a token sent only where the application sends no
    /// Authorization of its own.
    #[test]
    fn picks_and_sends_by_what_the_credentials_have() {
        let peer = Peer::new(crate::proto::HTTP, b"h".to_vec(), 80, None);
        let (none, b, br) = (AuthMethods::NONE, AuthMethods::BASIC, AuthMethods::BEARER);
        let pick = |secret: Secret<'_>, methods| {
            let mut auth = Auth::default();
            auth.start(AuthMethods::ANY, AuthMethods::NONE);
            let asked = auth.asked((Some(secret), &peer), (None, &peer), false, true);
            let offered = Offered {
                host: offered(methods),
                proxy: Challenges::default(),
            };
            AuthAct::of(401, &offered, &asked).picked
        };
        assert_eq!(pick(Secret::new(b"", b""), b), Some(none));
        assert_eq!(pick(Secret::new(b"u", b""), b), Some(b));
        assert_eq!(pick(Secret::new(b"", b"p"), b), Some(b));
        assert_eq!(pick(Secret::new(b"u", b"p"), b | br), Some(b));
        let token = |bearer: &[u8]| Credentials {
            user: b"u".to_vec(),
            password: Vec::new(),
            bearer: bearer.to_vec(),
            source: Source::Options,
            trusted: Trusted::own_url(),
        };
        assert_eq!(pick(token(b"t").secret(), b | br), Some(br));
        let request = AuthRequest {
            origin: &peer,
            method: b"GET",
            uri: b"/",
            get_or_head: true,
            trusted: Some(Trusted::own_url()),
        };
        let send = |c: &Credentials, custom| {
            let mut side = PeerAuth::default();
            side.start(br);
            side.output(Some(c.secret()), custom, &request, |_| Ok(()))
                .unwrap()
                .header
        };
        assert_eq!(send(&token(b"t"), false), Some((br, b"t".to_vec())));
        assert_eq!(send(&token(b"t"), true), None, "the application's own");
        assert_eq!(send(&token(b""), false), None, "no token");
    }

    /// AWS SigV4 wanted alone is in use at once, sending nothing itself:
    /// the request is signed where it is made. A proxy never uses it.
    #[test]
    fn aws_sigv4_is_used_at_once_and_never_by_a_proxy() {
        let peer = Peer::new(crate::proto::HTTP, b"h".to_vec(), 80, None);
        let request = AuthRequest {
            origin: &peer,
            method: b"GET",
            uri: b"/",
            get_or_head: true,
            trusted: Some(Trusted::own_url()),
        };
        let sigv4 = AuthMethods::AWS_SIGV4;
        let mut auth = Auth::default();
        auth.start(sigv4, sigv4);
        let secret = || Some(Secret::new(b"u", b"p"));
        let mut output = |side| {
            let out = auth
                .side(side)
                .output(secret(), false, &request, |_| Ok(()))
                .unwrap();
            (out.used, out.header, out.probe)
        };
        assert_eq!(output(Side::Host), (sigv4, None, false));
        assert_eq!(output(Side::Proxy), (AuthMethods::NONE, None, false));
    }

    /// A message signature wanted alone is in use at once, with
    /// credentials or without, sending nothing itself: the request is
    /// signed where it is made. Not to an origin the application's
    /// settings may not go to, and never to a proxy.
    #[test]
    fn a_message_signature_is_used_at_once_and_never_by_a_proxy() {
        let peer = Peer::new(crate::proto::HTTP, b"h".to_vec(), 80, None);
        let sig = AuthMethods::HTTPSIG;
        for (secret, trusted, used) in [
            (None, true, sig),
            (Some(Secret::new(b"u", b"p")), true, sig),
            (None, false, AuthMethods::NONE),
        ] {
            let request = AuthRequest {
                origin: &peer,
                method: b"GET",
                uri: b"/",
                get_or_head: true,
                trusted: trusted.then(Trusted::own_url),
            };
            let mut auth = Auth::default();
            auth.start(sig, sig);
            let mut output = |side| {
                let out = auth
                    .side(side)
                    .output(secret, false, &request, |_| Ok(()))
                    .unwrap();
                (out.used, out.header, out.probe)
            };
            assert_eq!(output(Side::Host), (used, None, false), "{trusted}");
            assert_eq!(output(Side::Proxy), (AuthMethods::NONE, None, false));
            assert!(auth.side(Side::Host).done);
        }
    }

    /// The values the C tool sends, and RFC 4648's vectors.
    #[test]
    fn encodes_basic_as_c() {
        let basic = |u: &[u8], p: &[u8]| {
            let secret = Secret::new(u, p);
            secret
                .basic()
                .unwrap()
                .map(|b| String::from_utf8(b).unwrap())
        };
        assert_eq!(basic(b"", b"example").as_deref(), Some("OmV4YW1wbGU="));
        assert_eq!(basic(b"u", b"").as_deref(), Some("dTo="));
        assert_eq!(basic(b"a\x01b", b"x").as_deref(), Some("YQFiOng="));
        assert_eq!(basic(b"fo", b"").as_deref(), Some("Zm86"));
        assert_eq!(basic(b"foob", b"r").as_deref(), Some("Zm9vYjpy"));
        // `http://@host/` and `http://:@host/` send none.
        assert_eq!(basic(b"", b""), None);
    }

    /// Words of challenges, and challenges whole.
    const CHALLENGE_WORDS: &[&[u8]] = &[
        b"Basic",
        b"Digest",
        b"Bearer",
        b"NTLM",
        b" ",
        b"\t",
        b",",
        b", ",
        b"=",
        b"\"",
        b"realm=\"r\"",
        b"nonce=\"n\"",
        b"qop=\"auth\"",
        b"qop=auth-int",
        b"stale=true",
        b"algorithm=MD5",
        b"algorithm=SHA-256-SESS",
        b"opaque=\"o\"",
        b"\\",
        b"\r\n",
    ];
    const CHALLENGES: &[&[u8]] = &[
        b"Basic realm=\"x\"",
        b"Digest realm=\"r\", nonce=\"1\", qop=\"auth,auth-int\", algorithm=MD5-sess, \
          opaque=\"o\", Basic",
        b"Bearer, Basic realm=\"x\", Digest nonce=\"2\", stale=true",
        b"Digest nonce=\"a\\\"b\", userhash=true, algorithm=SHA-512-256",
    ];

    proptest::proptest! {
        #![proptest_config(crate::untrusted::config(256))]

        /// Any challenges, read one line after another into what a
        /// response offered, then acted on for any request: no panic,
        /// and only the methods there are offered.
        #[test]
        fn any_challenges_are_read(
            values in proptest::collection::vec(
                crate::untrusted::input(CHALLENGE_WORDS, CHALLENGES, 12), 1..4),
            asked in arbitrary::auth_asked(),
            code in proptest::prop_oneof![
                proptest::strategy::Just(401u16),
                proptest::strategy::Just(407),
                100..600u16,
            ],
        ) {
            let mut offered = Offered::default();
            for v in &values {
                let sides = [
                    (&mut offered.host, &asked.host),
                    (&mut offered.proxy, &asked.proxy),
                ];
                for (challenges, side) in sides {
                    let heard = challenges.read(v, side).expect("no allocation fails");
                    proptest::prop_assert!(heard.notes().count() <= HEARD);
                }
            }
            let known = AuthMethods::BASIC | AuthMethods::DIGEST | AuthMethods::BEARER;
            for c in [&offered.host, &offered.proxy] {
                proptest::prop_assert_eq!(c.offered & !known, AuthMethods::NONE);
            }
            let act = AuthAct::of(code, &offered, &asked);
            act.fails(code, &asked);
        }
    }
}
