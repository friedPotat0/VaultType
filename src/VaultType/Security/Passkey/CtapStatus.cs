namespace VaultType.Security.Passkey;

// CTAP2 status codes (FIDO Client to Authenticator Protocol, section "Error responses"). A CTAP
// response is this single byte, optionally followed by a CBOR map when the status is Ok.
internal enum CtapStatus : byte
{
    Ok = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    CborUnexpectedType = 0x11,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    CredentialExcluded = 0x19,
    UnsupportedAlgorithm = 0x26,
    OperationDenied = 0x27,
    KeepAliveCancel = 0x2D,
    NoCredentials = 0x2E,
    NotAllowed = 0x30,
    PinRequired = 0x36,
    UserActionTimeout = 0x3A,
    OtherError = 0x7F,
}
