//! rustls-ffi's mapping of rustls's errors, one of each mapped as
//! `librustls/src/error.rs` maps it, the unknown ones into the catch-all,
//! and the words and the certificate errors as its own tests and its
//! library say them.

use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::KeyExchangeAlgorithm;
use rustls::pki_types::{ServerName, UnixTime};
use rustls::server::VerifierBuilderError;
use rustls::{
    AlertDescription, CertRevocationListError, CertificateError, ContentType,
    EncryptedClientHelloError, Error, ExtendedKeyPurpose, HandshakeType, InconsistentKeys,
    InvalidMessage, OtherError, PeerIncompatible, PeerMisbehaved,
};

use crate::result::{Code, map_error, map_verifier_builder_error};

fn other() -> OtherError {
    OtherError(Arc::new(std::io::Error::other("x")))
}

/// Each error rustls-ffi names is its own result.
#[test]
fn each_error_is_rustls_ffi_s_result() {
    let table: Vec<(Error, Code)> = vec![
        (
            Error::AlertReceived(AlertDescription::CloseNotify),
            Code::AlertCloseNotify,
        ),
        (
            Error::AlertReceived(AlertDescription::UnexpectedMessage),
            Code::AlertUnexpectedMessage,
        ),
        (
            Error::AlertReceived(AlertDescription::BadRecordMac),
            Code::AlertBadRecordMac,
        ),
        (
            Error::AlertReceived(AlertDescription::DecryptionFailed),
            Code::AlertDecryptionFailed,
        ),
        (
            Error::AlertReceived(AlertDescription::RecordOverflow),
            Code::AlertRecordOverflow,
        ),
        (
            Error::AlertReceived(AlertDescription::DecompressionFailure),
            Code::AlertDecompressionFailure,
        ),
        (
            Error::AlertReceived(AlertDescription::HandshakeFailure),
            Code::AlertHandshakeFailure,
        ),
        (
            Error::AlertReceived(AlertDescription::NoCertificate),
            Code::AlertNoCertificate,
        ),
        (
            Error::AlertReceived(AlertDescription::BadCertificate),
            Code::AlertBadCertificate,
        ),
        (
            Error::AlertReceived(AlertDescription::UnsupportedCertificate),
            Code::AlertUnsupportedCertificate,
        ),
        (
            Error::AlertReceived(AlertDescription::CertificateRevoked),
            Code::AlertCertificateRevoked,
        ),
        (
            Error::AlertReceived(AlertDescription::CertificateExpired),
            Code::AlertCertificateExpired,
        ),
        (
            Error::AlertReceived(AlertDescription::CertificateUnknown),
            Code::AlertCertificateUnknown,
        ),
        (
            Error::AlertReceived(AlertDescription::IllegalParameter),
            Code::AlertIllegalParameter,
        ),
        (
            Error::AlertReceived(AlertDescription::UnknownCA),
            Code::AlertUnknownCA,
        ),
        (
            Error::AlertReceived(AlertDescription::AccessDenied),
            Code::AlertAccessDenied,
        ),
        (
            Error::AlertReceived(AlertDescription::DecodeError),
            Code::AlertDecodeError,
        ),
        (
            Error::AlertReceived(AlertDescription::DecryptError),
            Code::AlertDecryptError,
        ),
        (
            Error::AlertReceived(AlertDescription::ExportRestriction),
            Code::AlertExportRestriction,
        ),
        (
            Error::AlertReceived(AlertDescription::ProtocolVersion),
            Code::AlertProtocolVersion,
        ),
        (
            Error::AlertReceived(AlertDescription::InsufficientSecurity),
            Code::AlertInsufficientSecurity,
        ),
        (
            Error::AlertReceived(AlertDescription::InternalError),
            Code::AlertInternalError,
        ),
        (
            Error::AlertReceived(AlertDescription::InappropriateFallback),
            Code::AlertInappropriateFallback,
        ),
        (
            Error::AlertReceived(AlertDescription::UserCanceled),
            Code::AlertUserCanceled,
        ),
        (
            Error::AlertReceived(AlertDescription::NoRenegotiation),
            Code::AlertNoRenegotiation,
        ),
        (
            Error::AlertReceived(AlertDescription::MissingExtension),
            Code::AlertMissingExtension,
        ),
        (
            Error::AlertReceived(AlertDescription::UnsupportedExtension),
            Code::AlertUnsupportedExtension,
        ),
        (
            Error::AlertReceived(AlertDescription::CertificateUnobtainable),
            Code::AlertCertificateUnobtainable,
        ),
        (
            Error::AlertReceived(AlertDescription::UnrecognisedName),
            Code::AlertUnrecognisedName,
        ),
        (
            Error::AlertReceived(AlertDescription::BadCertificateStatusResponse),
            Code::AlertBadCertificateStatusResponse,
        ),
        (
            Error::AlertReceived(AlertDescription::BadCertificateHashValue),
            Code::AlertBadCertificateHashValue,
        ),
        (
            Error::AlertReceived(AlertDescription::UnknownPSKIdentity),
            Code::AlertUnknownPSKIdentity,
        ),
        (
            Error::AlertReceived(AlertDescription::CertificateRequired),
            Code::AlertCertificateRequired,
        ),
        (
            Error::AlertReceived(AlertDescription::NoApplicationProtocol),
            Code::AlertNoApplicationProtocol,
        ),
        (
            Error::AlertReceived(AlertDescription::Unknown(250)),
            Code::AlertUnknown,
        ),
        (
            Error::InvalidCertRevocationList(CertRevocationListError::BadSignature),
            Code::CertRevocationListBadSignature,
        ),
        (
            Error::InvalidCertRevocationList(
                CertRevocationListError::UnsupportedSignatureAlgorithmContext {
                    signature_algorithm_id: vec![],
                    supported_algorithms: vec![],
                },
            ),
            Code::CertRevocationListUnsupportedSignatureAlgorithm,
        ),
        (
            Error::InvalidCertRevocationList(CertRevocationListError::InvalidCrlNumber),
            Code::CertRevocationListInvalidCrlNumber,
        ),
        (
            Error::InvalidCertRevocationList(
                CertRevocationListError::InvalidRevokedCertSerialNumber,
            ),
            Code::CertRevocationListInvalidRevokedCertSerialNumber,
        ),
        (
            Error::InvalidCertRevocationList(CertRevocationListError::IssuerInvalidForCrl),
            Code::CertRevocationListIssuerInvalidForCrl,
        ),
        (
            Error::InvalidCertRevocationList(CertRevocationListError::Other(other())),
            Code::CertRevocationListOtherError,
        ),
        (
            Error::InvalidCertRevocationList(CertRevocationListError::ParseError),
            Code::CertRevocationListParseError,
        ),
        (
            Error::InvalidCertRevocationList(CertRevocationListError::UnsupportedCrlVersion),
            Code::CertRevocationListUnsupportedCrlVersion,
        ),
        (
            Error::InvalidCertRevocationList(CertRevocationListError::UnsupportedCriticalExtension),
            Code::CertRevocationListUnsupportedCriticalExtension,
        ),
        (
            Error::InvalidCertRevocationList(CertRevocationListError::UnsupportedDeltaCrl),
            Code::CertRevocationListUnsupportedDeltaCrl,
        ),
        (
            Error::InvalidCertRevocationList(CertRevocationListError::UnsupportedIndirectCrl),
            Code::CertRevocationListUnsupportedIndirectCrl,
        ),
        (
            Error::InvalidCertRevocationList(CertRevocationListError::UnsupportedRevocationReason),
            Code::CertRevocationListUnsupportedRevocationReason,
        ),
        (
            Error::InvalidMessage(InvalidMessage::HandshakePayloadTooLarge),
            Code::MessageHandshakePayloadTooLarge,
        ),
        (
            Error::InvalidMessage(InvalidMessage::CertificatePayloadTooLarge),
            Code::MessageCertificatePayloadTooLarge,
        ),
        (
            Error::InvalidMessage(InvalidMessage::InvalidCcs),
            Code::MessageInvalidCcs,
        ),
        (
            Error::InvalidMessage(InvalidMessage::InvalidContentType),
            Code::MessageInvalidContentType,
        ),
        (
            Error::InvalidMessage(InvalidMessage::InvalidCertificateStatusType),
            Code::MessageInvalidCertStatusType,
        ),
        (
            Error::InvalidMessage(InvalidMessage::InvalidCertRequest),
            Code::MessageInvalidCertRequest,
        ),
        (
            Error::InvalidMessage(InvalidMessage::InvalidDhParams),
            Code::MessageInvalidDhParams,
        ),
        (
            Error::InvalidMessage(InvalidMessage::InvalidEmptyPayload),
            Code::MessageInvalidEmptyPayload,
        ),
        (
            Error::InvalidMessage(InvalidMessage::InvalidKeyUpdate),
            Code::MessageInvalidKeyUpdate,
        ),
        (
            Error::InvalidMessage(InvalidMessage::InvalidServerName),
            Code::MessageInvalidServerName,
        ),
        (
            Error::InvalidMessage(InvalidMessage::MessageTooLarge),
            Code::MessageTooLarge,
        ),
        (
            Error::InvalidMessage(InvalidMessage::MessageTooShort),
            Code::MessageTooShort,
        ),
        (
            Error::InvalidMessage(InvalidMessage::MissingData("x")),
            Code::MessageMissingData,
        ),
        (
            Error::InvalidMessage(InvalidMessage::MissingKeyExchange),
            Code::MessageMissingKeyExchange,
        ),
        (
            Error::InvalidMessage(InvalidMessage::NoSignatureSchemes),
            Code::MessageNoSignatureSchemes,
        ),
        (
            Error::InvalidMessage(InvalidMessage::TrailingData("x")),
            Code::MessageTrailingData,
        ),
        (
            Error::InvalidMessage(InvalidMessage::UnexpectedMessage("x")),
            Code::MessageUnexpectedMessage,
        ),
        (
            Error::InvalidMessage(InvalidMessage::UnknownProtocolVersion),
            Code::MessageUnknownProtocolVersion,
        ),
        (
            Error::InvalidMessage(InvalidMessage::UnsupportedCompression),
            Code::MessageUnsupportedCompression,
        ),
        (
            Error::InvalidMessage(InvalidMessage::UnsupportedCurveType),
            Code::MessageUnsupportedCurveType,
        ),
        (
            Error::InvalidMessage(InvalidMessage::UnsupportedKeyExchangeAlgorithm(
                KeyExchangeAlgorithm::ECDHE,
            )),
            Code::MessageUnsupportedCompression,
        ),
        (
            Error::InvalidCertificate(CertificateError::BadEncoding),
            Code::CertEncodingBad,
        ),
        (
            Error::InvalidCertificate(CertificateError::Expired),
            Code::CertExpired,
        ),
        (
            Error::InvalidCertificate(CertificateError::ExpiredContext {
                time: UnixTime::since_unix_epoch(Duration::from_secs(2)),
                not_after: UnixTime::since_unix_epoch(Duration::from_secs(1)),
            }),
            Code::CertExpired,
        ),
        (
            Error::InvalidCertificate(CertificateError::NotValidYet),
            Code::CertNotYetValid,
        ),
        (
            Error::InvalidCertificate(CertificateError::NotValidYetContext {
                time: UnixTime::since_unix_epoch(Duration::from_secs(1)),
                not_before: UnixTime::since_unix_epoch(Duration::from_secs(2)),
            }),
            Code::CertNotYetValid,
        ),
        (
            Error::InvalidCertificate(CertificateError::Revoked),
            Code::CertRevoked,
        ),
        (
            Error::InvalidCertificate(CertificateError::UnhandledCriticalExtension),
            Code::CertUnhandledCriticalExtension,
        ),
        (
            Error::InvalidCertificate(CertificateError::UnknownIssuer),
            Code::CertUnknownIssuer,
        ),
        (
            Error::InvalidCertificate(CertificateError::UnknownRevocationStatus),
            Code::CertUnknownRevocationStatus,
        ),
        (
            Error::InvalidCertificate(CertificateError::ExpiredRevocationList),
            Code::CertExpiredRevocationList,
        ),
        (
            Error::InvalidCertificate(CertificateError::ExpiredRevocationListContext {
                time: UnixTime::since_unix_epoch(Duration::from_secs(2)),
                next_update: UnixTime::since_unix_epoch(Duration::from_secs(1)),
            }),
            Code::CertExpiredRevocationList,
        ),
        (
            Error::InvalidCertificate(CertificateError::BadSignature),
            Code::CertBadSignature,
        ),
        (
            Error::InvalidCertificate(CertificateError::UnsupportedSignatureAlgorithmContext {
                signature_algorithm_id: vec![],
                supported_algorithms: vec![],
            }),
            Code::CertUnsupportedSignatureAlgorithm,
        ),
        (
            Error::InvalidCertificate(CertificateError::NotValidForName),
            Code::CertNotValidForName,
        ),
        (
            Error::InvalidCertificate(CertificateError::NotValidForNameContext {
                expected: ServerName::try_from("a.example").unwrap(),
                presented: vec![],
            }),
            Code::CertNotValidForName,
        ),
        (
            Error::InvalidCertificate(CertificateError::InvalidPurpose),
            Code::CertInvalidPurpose,
        ),
        (
            Error::InvalidCertificate(CertificateError::InvalidPurposeContext {
                required: ExtendedKeyPurpose::ServerAuth,
                presented: vec![],
            }),
            Code::CertInvalidPurpose,
        ),
        (
            Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure),
            Code::CertApplicationVerificationFailure,
        ),
        (
            Error::InvalidEncryptedClientHello(EncryptedClientHelloError::InvalidConfigList),
            Code::InvalidEncryptedClientHelloInvalidConfigList,
        ),
        (
            Error::InvalidEncryptedClientHello(EncryptedClientHelloError::NoCompatibleConfig),
            Code::InvalidEncryptedClientHelloNoCompatibleConfig,
        ),
        (
            Error::InvalidEncryptedClientHello(EncryptedClientHelloError::SniRequired),
            Code::InvalidEncryptedClientHelloSniRequired,
        ),
        (
            Error::InappropriateMessage {
                expect_types: vec![ContentType::Alert],
                got_type: ContentType::Handshake,
            },
            Code::InappropriateMessage,
        ),
        (
            Error::InappropriateHandshakeMessage {
                expect_types: vec![HandshakeType::Finished],
                got_type: HandshakeType::ClientHello,
            },
            Code::InappropriateHandshakeMessage,
        ),
        (
            Error::NoCertificatesPresented,
            Code::NoCertificatesPresented,
        ),
        (Error::DecryptError, Code::DecryptError),
        (
            Error::PeerIncompatible(PeerIncompatible::KeyShareExtensionRequired),
            Code::PeerIncompatibleError,
        ),
        (
            Error::PeerMisbehaved(PeerMisbehaved::BadCertChainExtensions),
            Code::PeerMisbehavedError,
        ),
        (Error::UnsupportedNameType, Code::UnsupportedNameType),
        (Error::EncryptError, Code::EncryptError),
        (Error::FailedToGetCurrentTime, Code::FailedToGetCurrentTime),
        (Error::FailedToGetRandomBytes, Code::FailedToGetRandomBytes),
        (Error::HandshakeNotComplete, Code::HandshakeNotComplete),
        (
            Error::PeerSentOversizedRecord,
            Code::PeerSentOversizedRecord,
        ),
        (Error::NoApplicationProtocol, Code::NoApplicationProtocol),
        (Error::BadMaxFragmentSize, Code::BadMaxFragmentSize),
        (Error::General("x".into()), Code::General),
        (
            Error::InconsistentKeys(InconsistentKeys::KeyMismatch),
            Code::InconsistentKeysKeysMismatch,
        ),
        (
            Error::InconsistentKeys(InconsistentKeys::Unknown),
            Code::InconsistentKeysUnknown,
        ),
    ];
    for (error, code) in table {
        let said = format!("{error:?}");
        assert_eq!(map_error(error), code, "{said}");
    }
}

/// A verifier that does not build is said as rustls-ffi says it.
#[test]
fn a_verifier_builder_s_error_is_rustls_ffi_s_result() {
    assert_eq!(
        map_verifier_builder_error(VerifierBuilderError::NoRootAnchors),
        Code::ClientCertVerifierBuilderNoRootAnchors
    );
    assert_eq!(
        map_verifier_builder_error(VerifierBuilderError::InvalidCrl(
            CertRevocationListError::BadSignature
        )),
        Code::CertRevocationListBadSignature
    );
}

/// Each result's words, and whether it is the peer's certificate's, as
/// rustls-ffi 0.15.5's library says them (`rustls_error`,
/// `rustls_result_is_cert_error`).
#[test]
fn each_result_is_said_as_rustls_ffi_says_it() {
    let table: &[(Code, bool, &str)] = &[
        (Code::Ok, false, "OK"),
        (Code::Io, false, "I/O error"),
        (Code::NullParameter, false, "a parameter was NULL"),
        (
            Code::InvalidDnsNameError,
            false,
            "server name was malformed (not a valid hostname or IP address)",
        ),
        (Code::Panic, false, "a Rust component panicked"),
        (
            Code::CertificateParseError,
            false,
            "error parsing certificate",
        ),
        (
            Code::PrivateKeyParseError,
            false,
            "error parsing private key",
        ),
        (
            Code::InsufficientSize,
            false,
            "provided buffer is of insufficient size",
        ),
        (Code::NotFound, false, "the item was not found"),
        (
            Code::InvalidParameter,
            false,
            "a parameter had an invalid value",
        ),
        (
            Code::UnexpectedEof,
            false,
            "peer closed TCP connection without first closing TLS connection",
        ),
        (
            Code::PlaintextEmpty,
            false,
            "no plaintext available; call rustls_connection_read_tls again",
        ),
        (
            Code::AcceptorNotReady,
            false,
            "rustls_acceptor not ready yet; read more TLS bytes into it",
        ),
        (
            Code::AlreadyUsed,
            false,
            "tried to use a rustls struct after it had been converted to another struct",
        ),
        (
            Code::CertificateRevocationListParseError,
            false,
            "error parsing certificate revocation list (CRL)",
        ),
        (
            Code::NoServerCertVerifier,
            false,
            "no server certificate verifier was configured on the client config builder",
        ),
        (
            Code::NoDefaultCryptoProvider,
            false,
            "no default process-wide crypto provider has been installed",
        ),
        (
            Code::GetRandomFailed,
            false,
            "failed to get random bytes from the crypto provider",
        ),
        (
            Code::NoCertResolver,
            false,
            "no certificate resolver was configured",
        ),
        (
            Code::HpkeError,
            false,
            "an error occurred with the selected HPKE suite",
        ),
        (
            Code::BuilderIncompatibleTlsVersions,
            false,
            "the client config builder specifies incompatible TLS versions for the requested feature",
        ),
        (
            Code::NoCertificatesPresented,
            false,
            "peer sent no certificates",
        ),
        (Code::DecryptError, false, "cannot decrypt peer's message"),
        (
            Code::FailedToGetCurrentTime,
            false,
            "failed to get current time",
        ),
        (Code::HandshakeNotComplete, false, "handshake not complete"),
        (
            Code::PeerSentOversizedRecord,
            false,
            "peer sent excess record size",
        ),
        (
            Code::NoApplicationProtocol,
            false,
            "peer doesn't support any known protocol",
        ),
        (Code::PeerIncompatibleError, false, "peer is incompatible"),
        (Code::PeerMisbehavedError, false, "peer misbehaved"),
        (
            Code::InappropriateMessage,
            false,
            "received unexpected message",
        ),
        (
            Code::InappropriateHandshakeMessage,
            false,
            "received unexpected handshake message",
        ),
        (Code::General, false, "general error"),
        (
            Code::FailedToGetRandomBytes,
            false,
            "failed to get random bytes",
        ),
        (
            Code::BadMaxFragmentSize,
            false,
            "the supplied max_fragment_size was too small or large",
        ),
        (
            Code::UnsupportedNameType,
            false,
            "presented server name type wasn't supported",
        ),
        (Code::EncryptError, false, "cannot encrypt message"),
        (
            Code::CertEncodingBad,
            true,
            "invalid peer certificate: BadEncoding",
        ),
        (Code::CertExpired, true, "invalid peer certificate: Expired"),
        (
            Code::CertNotYetValid,
            true,
            "invalid peer certificate: NotValidYet",
        ),
        (Code::CertRevoked, true, "invalid peer certificate: Revoked"),
        (
            Code::CertUnhandledCriticalExtension,
            true,
            "invalid peer certificate: UnhandledCriticalExtension",
        ),
        (
            Code::CertUnknownIssuer,
            true,
            "invalid peer certificate: UnknownIssuer",
        ),
        (
            Code::CertBadSignature,
            true,
            "invalid peer certificate: BadSignature",
        ),
        (
            Code::CertNotValidForName,
            true,
            "invalid peer certificate: NotValidForName",
        ),
        (
            Code::CertInvalidPurpose,
            true,
            "invalid peer certificate: InvalidPurpose",
        ),
        (
            Code::CertApplicationVerificationFailure,
            true,
            "invalid peer certificate: ApplicationVerificationFailure",
        ),
        (Code::CertOtherError, true, "unknown certificate error"),
        (
            Code::MessageHandshakePayloadTooLarge,
            false,
            "received corrupt message of type HandshakePayloadTooLarge",
        ),
        (
            Code::MessageInvalidCcs,
            false,
            "invalid change cipher spec (CCS) payload",
        ),
        (
            Code::MessageInvalidContentType,
            false,
            "received corrupt message of type InvalidContentType",
        ),
        (
            Code::MessageInvalidCertStatusType,
            false,
            "received corrupt message of type InvalidCertificateStatusType",
        ),
        (
            Code::MessageInvalidCertRequest,
            false,
            "invalid certificate request context",
        ),
        (
            Code::MessageInvalidDhParams,
            false,
            "peer's Diffie-Hellman (DH) parameters could not be decoded",
        ),
        (
            Code::MessageInvalidEmptyPayload,
            false,
            "received corrupt message of type InvalidEmptyPayload",
        ),
        (
            Code::MessageInvalidKeyUpdate,
            false,
            "received corrupt message of type InvalidKeyUpdate",
        ),
        (
            Code::MessageInvalidServerName,
            false,
            "received corrupt message of type InvalidServerName",
        ),
        (
            Code::MessageTooLarge,
            false,
            "received corrupt message of type MessageTooLarge",
        ),
        (
            Code::MessageTooShort,
            false,
            "received corrupt message of type MessageTooShort",
        ),
        (
            Code::MessageMissingData,
            false,
            "missing data for the named handshake payload value",
        ),
        (
            Code::MessageMissingKeyExchange,
            false,
            "peer did not advertise supported key exchange groups",
        ),
        (
            Code::MessageNoSignatureSchemes,
            false,
            "peer sent an empty list of signature schemes",
        ),
        (
            Code::MessageTrailingData,
            false,
            "trailing data found for the named handshake payload value",
        ),
        (
            Code::MessageUnexpectedMessage,
            false,
            "peer sent unexpected message type",
        ),
        (
            Code::MessageUnknownProtocolVersion,
            false,
            "received corrupt message of type UnknownProtocolVersion",
        ),
        (
            Code::MessageUnsupportedCompression,
            false,
            "received corrupt message of type UnsupportedCompression",
        ),
        (
            Code::MessageUnsupportedCurveType,
            false,
            "received corrupt message of type UnsupportedCurveType",
        ),
        (
            Code::MessageUnsupportedKeyExchangeAlgorithm,
            false,
            "peer sent an unsupported key exchange algorithm",
        ),
        (Code::MessageInvalidOther, false, "invalid message"),
        (
            Code::CertUnknownRevocationStatus,
            true,
            "invalid peer certificate: UnknownRevocationStatus",
        ),
        (
            Code::MessageCertificatePayloadTooLarge,
            false,
            "received corrupt message of type CertificatePayloadTooLarge",
        ),
        (
            Code::CertExpiredRevocationList,
            false,
            "invalid peer certificate: ExpiredRevocationList",
        ),
        (
            Code::CertUnsupportedSignatureAlgorithm,
            false,
            "unsupported certificate signature algorithm",
        ),
        (
            Code::AlertCloseNotify,
            false,
            "received fatal alert: CloseNotify",
        ),
        (
            Code::AlertUnexpectedMessage,
            false,
            "received fatal alert: UnexpectedMessage",
        ),
        (
            Code::AlertBadRecordMac,
            false,
            "received fatal alert: BadRecordMac",
        ),
        (
            Code::AlertDecryptionFailed,
            false,
            "received fatal alert: DecryptionFailed",
        ),
        (
            Code::AlertRecordOverflow,
            false,
            "received fatal alert: RecordOverflow",
        ),
        (
            Code::AlertDecompressionFailure,
            false,
            "received fatal alert: DecompressionFailure",
        ),
        (
            Code::AlertHandshakeFailure,
            false,
            "received fatal alert: HandshakeFailure",
        ),
        (
            Code::AlertNoCertificate,
            false,
            "received fatal alert: NoCertificate",
        ),
        (
            Code::AlertBadCertificate,
            false,
            "received fatal alert: BadCertificate",
        ),
        (
            Code::AlertUnsupportedCertificate,
            false,
            "received fatal alert: UnsupportedCertificate",
        ),
        (
            Code::AlertCertificateRevoked,
            false,
            "received fatal alert: CertificateRevoked",
        ),
        (
            Code::AlertCertificateExpired,
            false,
            "received fatal alert: CertificateExpired",
        ),
        (
            Code::AlertCertificateUnknown,
            false,
            "received fatal alert: CertificateUnknown",
        ),
        (
            Code::AlertIllegalParameter,
            false,
            "received fatal alert: IllegalParameter",
        ),
        (
            Code::AlertUnknownCA,
            false,
            "received fatal alert: UnknownCA",
        ),
        (
            Code::AlertAccessDenied,
            false,
            "received fatal alert: AccessDenied",
        ),
        (
            Code::AlertDecodeError,
            false,
            "received fatal alert: DecodeError",
        ),
        (
            Code::AlertDecryptError,
            false,
            "received fatal alert: DecryptError",
        ),
        (
            Code::AlertExportRestriction,
            false,
            "received fatal alert: ExportRestriction",
        ),
        (
            Code::AlertProtocolVersion,
            false,
            "received fatal alert: ProtocolVersion",
        ),
        (
            Code::AlertInsufficientSecurity,
            false,
            "received fatal alert: InsufficientSecurity",
        ),
        (
            Code::AlertInternalError,
            false,
            "received fatal alert: InternalError",
        ),
        (
            Code::AlertInappropriateFallback,
            false,
            "received fatal alert: InappropriateFallback",
        ),
        (
            Code::AlertUserCanceled,
            false,
            "received fatal alert: UserCanceled",
        ),
        (
            Code::AlertNoRenegotiation,
            false,
            "received fatal alert: NoRenegotiation",
        ),
        (
            Code::AlertMissingExtension,
            false,
            "received fatal alert: MissingExtension",
        ),
        (
            Code::AlertUnsupportedExtension,
            false,
            "received fatal alert: UnsupportedExtension",
        ),
        (
            Code::AlertCertificateUnobtainable,
            false,
            "received fatal alert: CertificateUnobtainable",
        ),
        (
            Code::AlertUnrecognisedName,
            false,
            "received fatal alert: UnrecognisedName",
        ),
        (
            Code::AlertBadCertificateStatusResponse,
            false,
            "received fatal alert: BadCertificateStatusResponse",
        ),
        (
            Code::AlertBadCertificateHashValue,
            false,
            "received fatal alert: BadCertificateHashValue",
        ),
        (
            Code::AlertUnknownPSKIdentity,
            false,
            "received fatal alert: UnknownPSKIdentity",
        ),
        (
            Code::AlertCertificateRequired,
            false,
            "received fatal alert: CertificateRequired",
        ),
        (
            Code::AlertNoApplicationProtocol,
            false,
            "received fatal alert: NoApplicationProtocol",
        ),
        (
            Code::AlertUnknown,
            false,
            "received fatal alert: AlertDescription(0x0)",
        ),
        (
            Code::CertRevocationListBadSignature,
            false,
            "invalid certificate revocation list: BadSignature",
        ),
        (
            Code::CertRevocationListInvalidCrlNumber,
            false,
            "invalid certificate revocation list: InvalidCrlNumber",
        ),
        (
            Code::CertRevocationListInvalidRevokedCertSerialNumber,
            false,
            "invalid certificate revocation list: InvalidRevokedCertSerialNumber",
        ),
        (
            Code::CertRevocationListIssuerInvalidForCrl,
            false,
            "invalid certificate revocation list: IssuerInvalidForCrl",
        ),
        (
            Code::CertRevocationListOtherError,
            false,
            "unknown certificate revocation list (CRL) error",
        ),
        (
            Code::CertRevocationListParseError,
            false,
            "invalid certificate revocation list: ParseError",
        ),
        (
            Code::CertRevocationListUnsupportedCrlVersion,
            false,
            "invalid certificate revocation list: UnsupportedCrlVersion",
        ),
        (
            Code::CertRevocationListUnsupportedCriticalExtension,
            false,
            "invalid certificate revocation list: UnsupportedCriticalExtension",
        ),
        (
            Code::CertRevocationListUnsupportedDeltaCrl,
            false,
            "invalid certificate revocation list: UnsupportedDeltaCrl",
        ),
        (
            Code::CertRevocationListUnsupportedIndirectCrl,
            false,
            "invalid certificate revocation list: UnsupportedIndirectCrl",
        ),
        (
            Code::CertRevocationListUnsupportedRevocationReason,
            false,
            "invalid certificate revocation list: UnsupportedRevocationReason",
        ),
        (
            Code::CertRevocationListUnsupportedSignatureAlgorithm,
            false,
            "unsupported CRL signature algorithm",
        ),
        (
            Code::ClientCertVerifierBuilderNoRootAnchors,
            false,
            "no root trust anchors provided",
        ),
        (
            Code::InconsistentKeysKeysMismatch,
            false,
            "keys may not be consistent: KeyMismatch",
        ),
        (
            Code::InconsistentKeysUnknown,
            false,
            "keys may not be consistent: Unknown",
        ),
        (
            Code::InvalidEncryptedClientHelloInvalidConfigList,
            false,
            "encrypted client hello failure: InvalidConfigList",
        ),
        (
            Code::InvalidEncryptedClientHelloNoCompatibleConfig,
            false,
            "encrypted client hello failure: NoCompatibleConfig",
        ),
        (
            Code::InvalidEncryptedClientHelloSniRequired,
            false,
            "encrypted client hello failure: SniRequired",
        ),
    ];
    for &(code, cert, words) in table {
        assert_eq!(code.to_string(), words, "{code:?}");
        assert_eq!(code.words().to_string(), words, "{code:?}");
        assert_eq!(code.is_cert_error(), cert, "{code:?}");
    }
}
