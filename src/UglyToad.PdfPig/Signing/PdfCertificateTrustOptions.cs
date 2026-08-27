using System.Security.Cryptography.X509Certificates;

namespace UglyToad.PdfPig.Signing;

/// <summary>
/// Specifies how PdfPig should build trust for signer or timestamp certificates.
/// </summary>
public sealed class PdfCertificateTrustOptions
{
    /// <summary>
    /// Gets a trust configuration that uses the system certificate store.
    /// </summary>
    public static PdfCertificateTrustOptions System { get; } = new()
    {
        UseSystemStore = true
    };

    /// <summary>
    /// Gets or sets a value indicating whether the system certificate store should be considered during trust evaluation.
    /// </summary>
    public bool UseSystemStore { get; init; }

    /// <summary>
    /// Gets or sets the additional trusted roots to use during certificate validation.
    /// </summary>
    public IReadOnlyList<X509Certificate2> AdditionalTrustedRoots { get; init; } = [];

    /// <summary>
    /// Gets or sets the additional intermediate certificates to use during certificate validation.
    /// </summary>
    public IReadOnlyList<X509Certificate2> AdditionalIntermediateCertificates { get; init; } = [];

    /// <summary>
    /// Gets or sets the revocation mode to use while building the certificate chain.
    /// </summary>
    public X509RevocationMode RevocationMode { get; init; } = X509RevocationMode.Online;

    /// <summary>
    /// Gets or sets the revocation scope to use while building the certificate chain.
    /// </summary>
    public X509RevocationFlag RevocationFlag { get; init; } = X509RevocationFlag.ExcludeRoot;

    /// <summary>
    /// Gets or sets the verification flags to apply while building the certificate chain.
    /// </summary>
    public X509VerificationFlags VerificationFlags { get; init; } = X509VerificationFlags.NoFlag;
}