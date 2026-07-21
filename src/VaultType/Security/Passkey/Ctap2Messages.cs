namespace VaultType.Security.Passkey;

// Decoded CTAP2 requests, reduced to the fields a passkey provider actually needs. Anything this
// authenticator does not implement (PIN protocols, largeBlob, credBlob, ...) is deliberately absent
// rather than parsed and ignored, so an unsupported request fails loudly instead of half-working.

internal sealed class CtapCredentialDescriptor
{
    public byte[] Id { get; init; } = Array.Empty<byte>();
    public string Type { get; init; } = "public-key";
}

internal sealed class CtapMakeCredentialRequest
{
    public byte[] ClientDataHash { get; init; } = Array.Empty<byte>();
    public string RpId { get; init; } = "";
    public string? RpName { get; init; }
    public byte[] UserId { get; init; } = Array.Empty<byte>();
    public string? UserName { get; init; }
    public string? UserDisplayName { get; init; }

    // COSE algorithm identifiers the relying party will accept, in order of preference.
    public List<int> Algorithms { get; init; } = new();

    // Credentials that must NOT be created again on this authenticator.
    public List<CtapCredentialDescriptor> ExcludeList { get; init; } = new();

    public bool RequireResidentKey { get; init; }
    public bool RequireUserVerification { get; init; }
}

internal sealed class CtapGetAssertionRequest
{
    public string RpId { get; init; } = "";
    public byte[] ClientDataHash { get; init; } = Array.Empty<byte>();

    // Credentials the relying party will accept; empty means "any discoverable credential for the RP".
    public List<CtapCredentialDescriptor> AllowList { get; init; } = new();

    public bool RequireUserPresence { get; init; } = true;
    public bool RequireUserVerification { get; init; }
}

// Raised when a request cannot be decoded or asks for something unsupported; carries the CTAP
// status to report back to Windows.
internal sealed class CtapException : Exception
{
    public CtapStatus Status { get; }

    public CtapException(CtapStatus status, string message) : base(message) => Status = status;
}
