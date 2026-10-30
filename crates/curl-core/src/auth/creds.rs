//! Who a request authenticates as, whatever its protocol: the user,
//! password, token and service the options, the URL or a `.netrc` entry
//! give (C's `struct Curl_creds`, `url_set_data_creds`), and the gate
//! that lets what the application said go only to the origin it was
//! said for (`Curl_auth_allowed_to_host`).

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::conn::Peer;
use crate::error::UrlErrorKind;
use crate::netrc::Found;
use crate::options::{Login, NetrcMode};
use crate::url::{GetOptions, Part, Url, decode_but_control, decode_but_zero};

/// Whether what the application said for the first origin may go to the
/// one the request is for: the only way to the tokens that let a custom
/// Host, an Authorization or a Cookie into a request.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CredentialGate {
    same: bool,
    trusted: bool,
}

/// The request is for the origin the transfer started with.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SameOrigin(());

/// Credentials may go to the request's origin (`Curl_auth_allowed_to_host`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Trusted(());

impl Trusted {
    /// Credentials the request's own URL carries go to its origin, which
    /// they were given for, wherever the transfer started
    /// (`url_set_data_creds`); so do those a `.netrc` entry gives for
    /// its host.
    pub(crate) fn own_url() -> Trusted {
        Trusted(())
    }
}

impl CredentialGate {
    /// The gate for the transfer's first request.
    pub(crate) const FIRST: CredentialGate = CredentialGate {
        same: true,
        trusted: true,
    };

    /// The gate for a request to `now` in a transfer that started at
    /// `initial`; `other_hosts` lets credentials follow it anywhere
    /// (`CURLOPT_UNRESTRICTED_AUTH`).
    pub(crate) fn new(initial: &Peer, now: &Peer, other_hosts: bool) -> CredentialGate {
        let same = initial == now;
        CredentialGate {
            same,
            trusted: same || other_hosts,
        }
    }

    pub(crate) fn same_origin(&self) -> Option<SameOrigin> {
        self.same.then_some(SameOrigin(()))
    }

    pub(crate) fn trusted(&self) -> Option<Trusted> {
        self.trusted.then_some(Trusted(()))
    }
}

/// Credentials kept to tell when a later request's are others
/// (`Curl_creds_same`): those a Digest challenge was answered with, or
/// those a connection authenticated with Negotiate is bound to.
#[derive(Debug)]
pub(crate) struct Answered {
    user: Vec<u8>,
    password: Vec<u8>,
    bearer: Vec<u8>,
    service: Vec<u8>,
    authzid: Vec<u8>,
}

/// The user and password a request authenticates with, decoded (C's
/// `struct Curl_creds`), and the leave to send them to its origin.
#[derive(Debug)]
pub(crate) struct Credentials {
    user: Vec<u8>,
    password: Vec<u8>,
    /// An OAuth 2.0 token, empty for none.
    bearer: Vec<u8>,
    /// The service the origin is authenticated as, empty for the
    /// protocol's (`sasl_service`).
    service: Vec<u8>,
    /// The identity a SASL login acts for, empty for the user's own
    /// (`sasl_authzid`).
    authzid: Vec<u8>,
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
    /// One decodes to a byte the scheme does not take, a zero byte or for
    /// most a control byte: "error extracting credentials from URL".
    Malformed,
    /// The application's user or password has a control byte, which the
    /// scheme does not take: "control code detected in credentials"
    /// (`CURLE_BAD_FUNCTION_ARGUMENT`).
    Control,
}

/// Which bytes a scheme takes in a user and a password: any but zero,
/// for those whose flags say so (`PROTOPT_USERPWDCTRL`, HTTP's), or no
/// control byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Takes {
    ControlBytes,
    NoControlBytes,
}

impl Takes {
    /// What `scheme`'s flags say it takes; a scheme libcurl does not know
    /// takes none, as its flags are none.
    pub(crate) fn of(scheme: Option<crate::conn::Scheme>) -> Takes {
        if scheme.is_some_and(crate::conn::Scheme::takes_control_bytes) {
            Takes::ControlBytes
        } else {
            Takes::NoControlBytes
        }
    }

    /// Whether `bytes` has none it refuses (`str_has_ctrl`).
    pub(crate) fn allows(self, bytes: &[u8]) -> bool {
        self == Takes::ControlBytes || !bytes.iter().any(|&b| b < 0x20)
    }
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
        takes: Takes,
    ) -> Result<Option<Credentials>, CredentialsError> {
        let (mut user, mut password, mut bearer) = (None, None, Vec::new());
        let (mut service, mut authzid) = (Vec::new(), Vec::new());
        if let Some(trusted) = trusted {
            user = login.user.as_deref().map(copy).transpose()?;
            password = login.password.as_deref().map(copy).transpose()?;
            bearer = login
                .bearer
                .as_deref()
                .map(copy)
                .transpose()?
                .unwrap_or_default();
            service = login
                .service
                .as_deref()
                .map(copy)
                .transpose()?
                .unwrap_or_default();
            authzid = login
                .authzid
                .as_deref()
                .map(copy)
                .transpose()?
                .unwrap_or_default();
            // `url_set_data_creds`: the application's, checked whole.
            let given = [user.as_deref(), password.as_deref()];
            if !given.iter().flatten().all(|g| takes.allows(g)) {
                return Err(CredentialsError::Control);
            }
            if let Some(user) = user.take_if(|u| !u.is_empty()) {
                return Ok(Some(Credentials {
                    user,
                    password: password.unwrap_or_default(),
                    bearer,
                    service,
                    authzid,
                    source: Source::Options,
                    trusted,
                }));
            }
        }
        if let Some((url_user, url_password)) = Self::of_url(url, takes)? {
            user = url_user.or(user);
            password = url_password.or(password);
        } else if user.is_none()
            && password.is_none()
            && bearer.is_empty()
            && service.is_empty()
            && authzid.is_empty()
        {
            return Ok(None);
        }
        // What the login left blank merged with the URL is the URL's,
        // even where the URL had nothing (`Curl_creds_merge`).
        Ok(Some(Credentials {
            user: user.unwrap_or_default(),
            password: password.unwrap_or_default(),
            bearer,
            service,
            authzid,
            source: Source::Url,
            // A login gets this far only trusted; the URL's own always.
            trusted: trusted.unwrap_or_else(Trusted::own_url),
        }))
    }

    /// A user, a password and a token, as the options give them.
    #[cfg(test)]
    pub(crate) fn of_options(user: &[u8], password: &[u8], bearer: &[u8]) -> Credentials {
        Credentials {
            user: user.to_vec(),
            password: password.to_vec(),
            bearer: bearer.to_vec(),
            service: Vec::new(),
            authzid: Vec::new(),
            source: Source::Options,
            trusted: Trusted::own_url(),
        }
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
        let (bearer, service, authzid) =
            credentials.map_or_else(Default::default, |c| (c.bearer, c.service, c.authzid));
        Credentials {
            user: found.user,
            password: found.password,
            bearer,
            service,
            authzid,
            source: Source::Netrc,
            trusted: Trusted::own_url(),
        }
    }

    /// What `url` carries, if it has a user or a password: decoded,
    /// rejecting a zero byte, and a control byte where the scheme `takes`
    /// none (HTTP takes them, `PROTOPT_USERPWDCTRL`).
    #[expect(
        clippy::type_complexity,
        reason = "a user and a password, each there or not"
    )]
    fn of_url(
        url: &Url,
        takes: Takes,
    ) -> Result<Option<(Option<Vec<u8>>, Option<Vec<u8>>)>, CredentialsError> {
        let decode = match takes {
            Takes::ControlBytes => decode_but_zero,
            Takes::NoControlBytes => decode_but_control,
        };
        let part = |what, missing| match url.get(what, GetOptions::NONE) {
            Ok(raw) => match decode(&raw) {
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

    /// Whether `other` authenticates as these do, compared in constant
    /// time: the user, the password, the token, the identity acted for
    /// and the service (`Curl_creds_same`).
    pub(crate) fn same(&self, other: &Credentials) -> bool {
        same_secret(&self.user, &other.user)
            & same_secret(&self.password, &other.password)
            & same_secret(&self.bearer, &other.bearer)
            & same_secret(&self.authzid, &other.authzid)
            & same_secret(&self.service, &other.service)
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
            service: &self.service,
            authzid: &self.authzid,
        }
    }

    /// The leave to send these to the request's origin.
    pub(crate) fn trusted(&self) -> Trusted {
        self.trusted
    }
}

/// What a request authenticates with to one peer: a user and a password,
/// a token and the service it is authenticated as, each empty for none.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Secret<'a> {
    user: &'a [u8],
    password: &'a [u8],
    bearer: &'a [u8],
    service: &'a [u8],
    authzid: &'a [u8],
}

impl<'a> Secret<'a> {
    /// A user, a password and a service, without a token: a proxy takes
    /// none.
    pub(crate) fn new(user: &'a [u8], password: &'a [u8], service: &'a [u8]) -> Secret<'a> {
        Secret {
            user,
            password,
            bearer: &[],
            service,
            authzid: &[],
        }
    }

    pub(crate) fn user(&self) -> &'a [u8] {
        self.user
    }

    pub(crate) fn password(&self) -> &'a [u8] {
        self.password
    }

    /// A user or a password, not both empty (`Curl_creds_has_user_or_pass`).
    pub(crate) fn has_user_or_password(&self) -> bool {
        !self.user.is_empty() || !self.password.is_empty()
    }

    /// The token, empty for none.
    pub(crate) fn bearer(&self) -> &'a [u8] {
        self.bearer
    }

    pub(crate) fn has_bearer(&self) -> bool {
        !self.bearer.is_empty()
    }

    /// The service the peer is authenticated as, if not the protocol's
    /// (`Curl_creds_has_sasl_service`).
    pub(crate) fn service(&self) -> Option<&'a [u8]> {
        (!self.service.is_empty()).then_some(self.service)
    }

    /// The identity a SASL login acts for, empty for the user's own.
    pub(crate) fn authzid(&self) -> &'a [u8] {
        self.authzid
    }

    /// The same, with an OAuth 2.0 token.
    #[cfg(test)]
    pub(crate) fn with_bearer(self, bearer: &'a [u8]) -> Secret<'a> {
        Secret { bearer, ..self }
    }

    /// The same, acting for `authzid`.
    #[cfg(test)]
    pub(crate) fn with_authzid(self, authzid: &'a [u8]) -> Secret<'a> {
        Secret { authzid, ..self }
    }

    /// These, kept to tell whether a Digest challenge answered with them
    /// is answered with others.
    pub(crate) fn answered(&self) -> Result<Answered, OutOfMemory> {
        Ok(Answered {
            user: copy(self.user)?,
            password: copy(self.password)?,
            bearer: copy(self.bearer)?,
            service: copy(self.service)?,
            authzid: copy(self.authzid)?,
        })
    }

    /// Whether these are those `answered` kept (`Curl_creds_same`, whose
    /// comparisons take the same time whatever the bytes).
    pub(crate) fn answers_as(&self, answered: &Answered) -> bool {
        same_secret(self.user, &answered.user)
            & same_secret(self.password, &answered.password)
            & same_secret(self.bearer, &answered.bearer)
            & same_secret(self.service, &answered.service)
            & same_secret(self.authzid, &answered.authzid)
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
        let bytes = self.user.iter().chain(b":").chain(self.password).copied();
        crate::base64::encode(bytes, len, &mut out)?;
        Ok(Some(out))
    }
}

/// A copy of `bytes`, made fallibly.
pub(crate) fn copy(bytes: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut v = Vec::new();
    v.try_extend_from_slice(bytes).map_err(|_| OutOfMemory)?;
    Ok(v)
}

/// Whether two secrets are the same, their bytes all compared whatever
/// the first difference (`Curl_timestrcmp`).
fn same_secret(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |d, (x, y)| d | (x ^ y)) == 0
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
        Ok(
            Credentials::for_request(login, trusted, &url, Takes::ControlBytes)?
                .map(|c| (c.user, c.password, c.source)),
        )
    }

    /// A scheme without `PROTOPT_USERPWDCTRL` takes no control byte in
    /// a user or a password: the URL's is malformed (test 894), the
    /// application's refused; HTTP's takes them, but a zero byte.
    #[test]
    fn control_bytes_are_refused_where_the_scheme_takes_none() {
        let take = |login: &Login, url: &str, takes| {
            let url = Url::parse(url.as_bytes(), ParseOptions::NONE).unwrap();
            Credentials::for_request(login, Some(Trusted::own_url()), &url, takes)
                .map(|c| c.is_some())
        };
        let cr = "pop3://us%0der:p@h/";
        assert_eq!(
            take(&Login::default(), cr, Takes::NoControlBytes),
            Err(CredentialsError::Malformed)
        );
        assert_eq!(take(&Login::default(), cr, Takes::ControlBytes), Ok(true));
        let zero = "pop3://us%00er:p@h/";
        assert_eq!(
            take(&Login::default(), zero, Takes::ControlBytes),
            Err(CredentialsError::Malformed)
        );
        let login = Login {
            user: Some(b"a\rb".to_vec()),
            ..Login::default()
        };
        assert_eq!(
            take(&login, "pop3://h/", Takes::NoControlBytes),
            Err(CredentialsError::Control)
        );
        assert_eq!(take(&login, "pop3://h/", Takes::ControlBytes), Ok(true));
        assert_eq!(
            Takes::of(crate::conn::Scheme::named(b"pop3")),
            Takes::NoControlBytes
        );
        assert_eq!(
            Takes::of(crate::conn::Scheme::named(b"http")),
            Takes::ControlBytes
        );
    }

    /// A SASL identity to act for comes with the application's
    /// credentials, and alone makes them.
    #[test]
    fn the_authzid_is_the_login_s() {
        let login = Login {
            authzid: Some(b"ursel".to_vec()),
            ..Login::default()
        };
        let url = Url::parse(b"pop3://kurt:x@h/", ParseOptions::NONE).unwrap();
        let c = Credentials::for_request(
            &login,
            Some(Trusted::own_url()),
            &url,
            Takes::NoControlBytes,
        )
        .unwrap()
        .unwrap();
        assert_eq!(c.secret().authzid(), b"ursel");
        let url = Url::parse(b"pop3://h/", ParseOptions::NONE).unwrap();
        let alone = Credentials::for_request(
            &login,
            Some(Trusted::own_url()),
            &url,
            Takes::NoControlBytes,
        );
        assert!(alone.unwrap().is_some());
    }

    /// As C's `url_set_data_creds` composes them: the login's user wins
    /// whole; with none, the URL's parts replace the login's; an
    /// untrusted login is not looked at.
    #[test]
    fn composes_the_login_and_the_url_s_as_c() {
        let login = |u: Option<&[u8]>, p: Option<&[u8]>| Login {
            user: u.map(<[u8]>::to_vec),
            password: p.map(<[u8]>::to_vec),
            ..Login::default()
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
            Credentials::for_request(&token, trusted, &url, Takes::ControlBytes)
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
            service: Vec::new(),
            authzid: Vec::new(),
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

    /// A service named makes credentials alone, as C's
    /// `url_set_data_creds` counts `CURLOPT_SERVICE_NAME`, and only for
    /// the origin the options go to; they are other credentials for
    /// another service, and the netrc's keep it.
    #[test]
    fn a_service_makes_credentials() {
        let login = Login {
            service: Some(b"web".to_vec()),
            ..Login::default()
        };
        let url = Url::parse(b"http://h/", ParseOptions::NONE).unwrap();
        let c =
            Credentials::for_request(&login, Some(Trusted::own_url()), &url, Takes::ControlBytes)
                .unwrap()
                .expect("credentials");
        assert_eq!(c.secret().service(), Some(&b"web"[..]));
        assert_eq!(c.secret().user(), b"");
        assert!(
            Credentials::for_request(&login, None, &url, Takes::ControlBytes)
                .unwrap()
                .is_none()
        );
        let other = Login {
            service: Some(b"other".to_vec()),
            ..Login::default()
        };
        let d =
            Credentials::for_request(&other, Some(Trusted::own_url()), &url, Takes::ControlBytes)
                .unwrap()
                .unwrap();
        assert!(!d.secret().answers_as(&c.secret().answered().unwrap()));
        assert!(c.secret().answers_as(&c.secret().answered().unwrap()));
        let found = Found {
            user: b"n".to_vec(),
            password: b"p".to_vec(),
        };
        let merged = Credentials::with_netrc(Some(c), found);
        assert_eq!(merged.secret().service(), Some(&b"web"[..]));
    }
}
