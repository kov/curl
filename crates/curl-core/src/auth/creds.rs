//! Who a request authenticates as, whatever its protocol: the user,
//! password, token and service the options, the URL or a `.netrc` entry
//! give (C's `struct Curl_creds`, `url_set_data_creds`), and the gate
//! that lets what the application said go only to the origin it was
//! said for (`Curl_auth_allowed_to_host`).

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::auth::gate::{CredentialGate, Leave, OriginTrusted, OwnLeave};
use crate::error::UrlErrorKind;
use crate::netrc::Found;
use crate::options::{Login, NetrcMode};
use crate::url::{GetOptions, Part, Url, decode_but_control, decode_but_zero};

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
/// `struct Curl_creds`), where they came from with the leave to send them
/// to its origin, and what only the application gives.
#[derive(Debug)]
pub(crate) struct Credentials {
    user: Vec<u8>,
    password: Vec<u8>,
    proof: Proof,
    /// What only the application gives, there only where the request's
    /// gate trusts its origin.
    app: Option<AppSecrets>,
}

/// Where credentials came from, each with what lets them go to the
/// request's origin: the application's login only through the gate; the
/// URL's by the gate's leave where the login gave to them, else by their
/// own; a `.netrc` entry's by its own.
#[derive(Clone, Copy, Debug)]
enum Proof {
    Options(OriginTrusted),
    Url(Leave),
    Netrc(OwnLeave),
}

impl Proof {
    fn source(self) -> Source {
        match self {
            Proof::Options(_) => Source::Options,
            Proof::Url(_) => Source::Url,
            Proof::Netrc(_) => Source::Netrc,
        }
    }
}

/// The application's OAuth 2.0 token, the service the origin is
/// authenticated as and the identity a SASL login acts for, at least one
/// of them given: made only for an origin the request's gate trusts.
#[derive(Debug)]
pub(crate) struct AppSecrets {
    /// Empty for none.
    bearer: Vec<u8>,
    /// Empty for the protocol's (`sasl_service`).
    service: Vec<u8>,
    /// Empty for the user's own (`sasl_authzid`).
    authzid: Vec<u8>,
}

impl AppSecrets {
    /// What `login` gives of them, for an origin the gate trusts; none if
    /// it gives none.
    fn of(login: &Login, _: OriginTrusted) -> Result<Option<AppSecrets>, OutOfMemory> {
        let given = |v: &Option<Vec<u8>>| v.as_deref().map(copy).transpose();
        let app = AppSecrets {
            bearer: given(&login.bearer)?.unwrap_or_default(),
            service: given(&login.service)?.unwrap_or_default(),
            authzid: given(&login.authzid)?.unwrap_or_default(),
        };
        let none = app.bearer.is_empty() && app.service.is_empty() && app.authzid.is_empty();
        Ok((!none).then_some(app))
    }

    fn try_clone(&self) -> Result<AppSecrets, OutOfMemory> {
        Ok(AppSecrets {
            bearer: copy(&self.bearer)?,
            service: copy(&self.service)?,
            authzid: copy(&self.authzid)?,
        })
    }
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
    /// A copy, for a connection matched by them that the request still
    /// authenticates with, as RTSP's is.
    pub(crate) fn try_clone(&self) -> Result<Credentials, OutOfMemory> {
        Ok(Credentials {
            user: copy(&self.user)?,
            password: copy(&self.password)?,
            proof: self.proof,
            app: self.app.as_ref().map(AppSecrets::try_clone).transpose()?,
        })
    }

    /// What a request to `url` authenticates with (`url_set_data_creds`):
    /// the application's `login`, if `trusted` lets it go to the URL's
    /// origin; then what the URL carries, if the login named no user,
    /// each part it has replacing the login's.
    pub(crate) fn for_request(
        login: &Login,
        gate: &CredentialGate,
        url: &Url,
        takes: Takes,
    ) -> Result<Option<Credentials>, CredentialsError> {
        // Nothing to take from either: none, without looking further.
        if login.gives_nothing() && !url.has_login() {
            return Ok(None);
        }
        let trusted = gate.trusted();
        let (mut user, mut password, mut app) = (None, None, None);
        if let Some(trusted) = trusted {
            user = login.user.as_deref().map(copy).transpose()?;
            password = login.password.as_deref().map(copy).transpose()?;
            app = AppSecrets::of(login, trusted)?;
            // `Curl_creds_create`'s check of what the application gave.
            let given = [user.as_deref(), password.as_deref()];
            if !given.iter().flatten().all(|g| takes.allows(g)) {
                return Err(CredentialsError::Control);
            }
            if let Some(user) = user.take_if(|u| !u.is_empty()) {
                return Ok(Some(Credentials {
                    user,
                    password: password.unwrap_or_default(),
                    proof: Proof::Options(trusted),
                    app,
                }));
            }
        }
        if let Some((url_user, url_password)) = Self::of_url(url, takes)? {
            user = url_user.or(user);
            password = url_password.or(password);
        } else if user.is_none() && password.is_none() && app.is_none() {
            return Ok(None);
        }
        // The URL's, the login's password under the URL's user if it gave
        // one: by the gate's leave where the login gave to them, else by
        // their own.
        let leave = trusted.map_or_else(|| Leave::own(OwnLeave::given()), Leave::of);
        Ok(Some(Credentials {
            user: user.unwrap_or_default(),
            password: password.unwrap_or_default(),
            proof: Proof::Url(leave),
            app,
        }))
    }

    /// A user, a password and a token, as the options give them.
    #[cfg(test)]
    pub(crate) fn of_options(user: &[u8], password: &[u8], bearer: &[u8]) -> Credentials {
        let app = (!bearer.is_empty()).then(|| AppSecrets {
            bearer: bearer.to_vec(),
            service: Vec::new(),
            authzid: Vec::new(),
        });
        Credentials {
            user: user.to_vec(),
            password: password.to_vec(),
            proof: Proof::Options(OriginTrusted::testing()),
            app,
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
        match c.proof.source() {
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
            proof: Proof::Netrc(OwnLeave::given()),
            // What the application gave the origin goes with the entry
            // for its host.
            app: credentials.and_then(|c| c.app),
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
        // Every field by name, so that one added does not compile until
        // it is compared, in `Secret::same`, or said why not.
        let Credentials {
            user: _,
            password: _,
            app: _,
            // Where they came from, and the leave to send them, decide
            // where they go, not who they are: C's `Curl_creds_same`
            // compares neither.
            proof: _,
        } = self;
        self.secret().same(&other.secret())
    }

    pub(crate) fn user(&self) -> &[u8] {
        &self.user
    }

    /// They are a `.netrc` file's.
    pub(crate) fn found_in_netrc(&self) -> bool {
        matches!(self.proof, Proof::Netrc(_))
    }

    /// Whether they are the URL's own (`CREDS_URL`).
    pub(crate) fn given_in_url(&self) -> bool {
        matches!(self.proof, Proof::Url(_))
    }

    /// What these authenticate with.
    pub(crate) fn secret(&self) -> Secret<'_> {
        let app = |part: fn(&AppSecrets) -> &[u8]| self.app.as_ref().map_or(&[][..], part);
        Secret {
            user: &self.user,
            password: &self.password,
            bearer: app(|a| &a.bearer),
            service: app(|a| &a.service),
            authzid: app(|a| &a.authzid),
        }
    }

    /// The leave to send these to the request's origin.
    pub(crate) fn leave(&self) -> Leave {
        match self.proof {
            Proof::Options(trusted) => Leave::of(trusted),
            Proof::Url(leave) => leave,
            Proof::Netrc(own) => Leave::own(own),
        }
    }

    /// Where they came from.
    #[cfg(test)]
    fn source(&self) -> Source {
        self.proof.source()
    }
}

/// What C's trace says of a request's credentials (`Curl_creds_trace`):
/// the user and the identity acted for as they are, whether there is a
/// password or a token, and where they came from.
#[derive(Debug)]
pub(crate) struct Shown {
    user: Vec<u8>,
    password: bool,
    authzid: Vec<u8>,
    bearer: bool,
    source: Source,
}

impl Shown {
    pub(crate) fn of(c: &Credentials) -> Result<Shown, OutOfMemory> {
        Ok(Shown {
            user: copy(&c.user)?,
            password: !c.password.is_empty(),
            authzid: copy(c.secret().authzid())?,
            bearer: c.secret().has_bearer(),
            source: c.proof.source(),
        })
    }

    /// The line's parts after its `msg: `: the user, `***` for a password
    /// there is, the identity, `***` for a token, and C's number for the
    /// source (`CREDS_*`).
    pub(crate) fn parts(&self) -> [&[u8]; 10] {
        let secret = |there: bool| -> &'static [u8] { if there { b"***" } else { b"" } };
        let source: &'static [u8] = match self.source {
            Source::Url => b"1",
            Source::Options => b"2",
            Source::Netrc => b"3",
        };
        [
            b"user=",
            &self.user,
            b", passwd=",
            secret(self.password),
            b", sasl_authzid=",
            &self.authzid,
            b", oauth_bearer=",
            secret(self.bearer),
            b", source=",
            source,
        ]
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
        let Answered {
            user,
            password,
            bearer,
            service,
            authzid,
        } = answered;
        self.same(&Secret {
            user,
            password,
            bearer,
            service,
            authzid,
        })
    }

    /// Whether these are `other` (`Curl_creds_same`): every part the
    /// same bytes, case and all, each compared in the same time whatever
    /// the bytes and all of them compared whatever the first says.
    pub(crate) fn same(&self, other: &Secret<'_>) -> bool {
        // Every field by name, so that one added does not compile until
        // it is compared here.
        let Secret {
            user,
            password,
            bearer,
            service,
            authzid,
        } = self;
        same_secret(user, other.user)
            & same_secret(password, other.password)
            & same_secret(bearer, other.bearer)
            & same_secret(service, other.service)
            & same_secret(authzid, other.authzid)
    }

    /// `user:password` in base64, what `Authorization: Basic` carries;
    /// nothing when both are empty (`Curl_creds_has_user_or_pass`).
    pub(crate) fn basic(&self) -> Result<Option<Vec<u8>>, OutOfMemory> {
        if self.user.is_empty() && self.password.is_empty() {
            return Ok(None);
        }
        // As C does: `user:password` put together, then encoded.
        let mut plain = Vec::new();
        plain
            .try_reserve_exact(self.user.len() + 1 + self.password.len())
            .map_err(|_| OutOfMemory)?;
        plain.try_extend_from_slice(self.user)?;
        plain.try_extend_from_slice(b":")?;
        plain.try_extend_from_slice(self.password)?;
        let mut out = Vec::new();
        crate::base64::encode(&plain, &mut out)?;
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
pub(crate) fn same_secret(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |d, (x, y)| d | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::url::ParseOptions;

    /// A user and a password.
    type Pair = (Vec<u8>, Vec<u8>);

    /// A gate that trusts the request's origin, or one that does not.
    fn gate(trusted: bool) -> CredentialGate {
        let peer = |host: &[u8]| {
            crate::conn::Peer::new(crate::conn::Scheme::HTTP, host.to_vec(), 80, None)
        };
        let first = peer(b"first.example");
        let now = if trusted {
            peer(b"first.example")
        } else {
            peer(b"other.example")
        };
        CredentialGate::testing(&first, &now, false)
    }

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
        Ok(
            Credentials::for_request(login, &gate(trusted), &url, Takes::ControlBytes)?
                .map(|c| (c.source(), c.user, c.password))
                .map(|(source, user, password)| (user, password, source)),
        )
    }

    /// A scheme without `PROTOPT_USERPWDCTRL` takes no control byte in
    /// a user or a password: the URL's is malformed (test 894), the
    /// application's refused; HTTP's takes them, but a zero byte.
    #[test]
    fn control_bytes_are_refused_where_the_scheme_takes_none() {
        let take = |login: &Login, url: &str, takes| {
            let url = Url::parse(url.as_bytes(), ParseOptions::NONE).unwrap();
            Credentials::for_request(login, &gate(true), &url, takes).map(|c| c.is_some())
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
        // Only the bytes below a space are control bytes (`str_has_ctrl`).
        assert!(Takes::NoControlBytes.allows(b"a b\x7f\xff"));
        assert!(!Takes::NoControlBytes.allows(b"a\x1fb"));
        assert!(Takes::ControlBytes.allows(b"a\x1fb"));
    }

    /// A `.netrc` entry for a host the gate shuts gives its own user and
    /// password, and nothing the application said: its OAuth 2.0 token,
    /// service and identity stay with the first origin, though the entry
    /// goes wherever the transfer started (CVE-2026-3783's rule). Where
    /// the gate lets them through, the entry keeps them.
    #[test]
    fn a_netrc_entry_does_not_trust_a_bearer() {
        let login = Login {
            bearer: Some(b"t0ken".to_vec()),
            service: Some(b"svc".to_vec()),
            authzid: Some(b"ursel".to_vec()),
            ..Login::default()
        };
        let url = Url::parse(b"imap://h/", ParseOptions::NONE).unwrap();
        for trusted in [false, true] {
            let given =
                Credentials::for_request(&login, &gate(trusted), &url, Takes::NoControlBytes)
                    .unwrap();
            let found = Found {
                user: b"n".to_vec(),
                password: b"p".to_vec(),
            };
            let c = Credentials::with_netrc(given, found);
            let secret = c.secret();
            assert_eq!((secret.user(), secret.password()), (&b"n"[..], &b"p"[..]));
            let kept: [&[u8]; 3] = [b"t0ken", b"svc", b"ursel"];
            let none: [&[u8]; 3] = [b"", b"", b""];
            let want = if trusted { kept } else { none };
            assert_eq!(
                [
                    secret.bearer(),
                    secret.service().unwrap_or_default(),
                    secret.authzid()
                ],
                want,
                "{trusted}"
            );
        }
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
        let c = Credentials::for_request(&login, &gate(true), &url, Takes::NoControlBytes)
            .unwrap()
            .unwrap();
        assert_eq!(c.secret().authzid(), b"ursel");
        let url = Url::parse(b"pop3://h/", ParseOptions::NONE).unwrap();
        let alone = Credentials::for_request(&login, &gate(true), &url, Takes::NoControlBytes);
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

    /// A user or a password the login gives, even empty, makes
    /// credentials where the URL has none; an empty token, service or
    /// identity does not (`Curl_creds_create`: the NULL credential is
    /// no user, no password and nothing in the rest). A URL with a user
    /// or a password, even empty, makes them with no login. Neither
    /// makes none.
    #[test]
    fn a_part_given_empty_still_makes_credentials() {
        let empty = || Some(Vec::new());
        let one = [
            Login {
                user: empty(),
                ..Login::default()
            },
            Login {
                password: empty(),
                ..Login::default()
            },
            Login {
                bearer: empty(),
                ..Login::default()
            },
            Login {
                service: empty(),
                ..Login::default()
            },
            Login {
                authzid: empty(),
                ..Login::default()
            },
        ];
        for (n, login) in one.iter().enumerate() {
            assert!(!login.gives_nothing(), "{login:?}");
            let made = with(login, true, "http://h/").unwrap();
            let want = (n < 2).then(|| (vec![], vec![], Source::Url));
            assert_eq!(made, want, "{login:?}");
        }
        let nothing = Login {
            delegation: crate::options::Delegation {
                by_policy: true,
                always: true,
            },
            ..Login::default()
        };
        assert!(nothing.gives_nothing());
        assert_eq!(with(&nothing, true, "http://h/"), Ok(None));
        for (url, has) in [
            ("http://h/", false),
            ("http://@h/", true),
            ("http://u@h/", true),
            ("http://:p@h/", true),
            ("http://:@h/", true),
        ] {
            let parsed = Url::parse(url.as_bytes(), ParseOptions::NONE).unwrap();
            assert_eq!(parsed.has_login(), has, "{url}");
            assert_eq!(creds(url).unwrap().is_some(), has, "{url}");
        }
        // A password set alone, as `curl_url_set` can, with no user.
        let mut url = Url::parse(b"http://h/", ParseOptions::NONE).unwrap();
        url.set(Part::Password, Some(b"p"), crate::url::SetOptions::NONE)
            .unwrap();
        assert!(url.has_login());
        let made =
            Credentials::for_request(&Login::default(), &gate(true), &url, Takes::ControlBytes)
                .unwrap()
                .map(|c| (c.user, c.password));
        assert_eq!(made, Some((vec![], b"p".to_vec())));
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
            Credentials::for_request(&token, &gate(trusted), &url, Takes::ControlBytes)
                .unwrap()
                .map(|c| (c.user.clone(), c.secret().bearer().to_vec()))
        };
        assert_eq!(bearer(true, "http://h/"), Some((vec![], b"t".to_vec())));
        assert_eq!(
            bearer(true, "http://u@h/"),
            Some((b"u".to_vec(), b"t".to_vec()))
        );
        assert_eq!(bearer(false, "http://h/"), None);
        assert_eq!(bearer(false, "http://u@h/"), Some((b"u".to_vec(), vec![])));
    }

    /// Credentials are the same only when every part is the same bytes:
    /// a user or password differing only in case is another login
    /// (CVE-2016-8616), and so is another token, service or identity
    /// acted for (CVE-2022-22576, CVE-2026-8458). Both comparisons, of
    /// a connection's login and of what a Digest challenge was answered
    /// with, say so.
    #[test]
    fn credentials_are_the_same_only_byte_for_byte() {
        let url = Url::parse(b"pop3://h/", ParseOptions::NONE).unwrap();
        let make = |login: Login| {
            Credentials::for_request(&login, &gate(true), &url, Takes::ControlBytes)
                .unwrap()
                .expect("credentials")
        };
        let base = || Login {
            user: Some(b"u".to_vec()),
            password: Some(b"Secret".to_vec()),
            bearer: Some(b"t".to_vec()),
            service: Some(b"s".to_vec()),
            authzid: Some(b"z".to_vec()),
            ..Login::default()
        };
        let a = make(base());
        let kept = a.secret().answered().unwrap();
        assert!(a.same(&make(base())));
        assert!(make(base()).secret().answers_as(&kept));
        for (part, other) in [
            (
                "password",
                Login {
                    password: Some(b"secret".to_vec()),
                    ..base()
                },
            ),
            (
                "user",
                Login {
                    user: Some(b"U".to_vec()),
                    ..base()
                },
            ),
            (
                "bearer",
                Login {
                    bearer: Some(b"T".to_vec()),
                    ..base()
                },
            ),
            (
                "service",
                Login {
                    service: Some(b"S".to_vec()),
                    ..base()
                },
            ),
            (
                "authzid",
                Login {
                    authzid: Some(b"Z".to_vec()),
                    ..base()
                },
            ),
        ] {
            let b = make(other);
            assert!(!a.same(&b), "{part}");
            assert!(!b.same(&a), "{part}");
            assert!(!b.secret().answers_as(&kept), "{part}");
        }
    }

    /// As C's `url_set_data_creds_netrc` decides: never over the
    /// options', over the URL's to complete them or, if required, to
    /// replace the password, naming the URL's user.
    #[test]
    fn looks_in_netrc_as_c() {
        let creds = |user: &[u8], password: &[u8], source| Credentials {
            user: user.to_vec(),
            password: password.to_vec(),
            proof: match source {
                Source::Options => Proof::Options(OriginTrusted::testing()),
                Source::Url => Proof::Url(Leave::of(OriginTrusted::testing())),
                Source::Netrc => Proof::Netrc(OwnLeave::given()),
            },
            app: None,
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
        let c = Credentials::for_request(&login, &gate(true), &url, Takes::ControlBytes)
            .unwrap()
            .expect("credentials");
        assert_eq!(c.secret().service(), Some(&b"web"[..]));
        assert_eq!(c.secret().user(), b"");
        assert!(
            Credentials::for_request(&login, &gate(false), &url, Takes::ControlBytes)
                .unwrap()
                .is_none()
        );
        let other = Login {
            service: Some(b"other".to_vec()),
            ..Login::default()
        };
        let d = Credentials::for_request(&other, &gate(true), &url, Takes::ControlBytes)
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
