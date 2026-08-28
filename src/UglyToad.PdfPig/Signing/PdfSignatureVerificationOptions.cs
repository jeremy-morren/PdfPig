namespace UglyToad.PdfPig.Signing;

/// <summary>
/// Controls how PdfPig validates embedded PDF signatures and timestamps.
/// </summary>
public sealed class PdfSignatureVerificationOptions
{
    /// <summary>
    /// Gets or sets the trust configuration used for document signing certificates.
    /// </summary>
    public PdfCertificateTrustOptions SignatureTrust { get; set; } = PdfCertificateTrustOptions.System;

    /// <summary>
    /// Gets or sets the trust configuration used for RFC 3161 timestamp certificates.
    /// </summary>
    public PdfCertificateTrustOptions TimeStampTrust { get; set; } = PdfCertificateTrustOptions.System;

    /// <summary>
    /// Gets or sets the rules a signing certificate must satisfy, beyond building a trusted chain.
    /// </summary>
    /// <remarks>
    /// Defaults to <see cref="DocumentSigningEKUValidator"/>. Set your own implementation to accept
    /// certificates that declare their purpose some other way — European qualified certificates, for
    /// example, commonly carry no extended key usage and use QCStatements instead. Set to
    /// <see langword="null"/> to apply no rules beyond chain building.
    /// </remarks>
    public ICertificateValidator? SignatureCertificateValidator { get; set; } = new DocumentSigningEKUValidator();

    /// <summary>
    /// Gets or sets the rules a timestamp authority certificate must satisfy, beyond building a
    /// trusted chain.
    /// </summary>
    /// <remarks>
    /// Defaults to <see cref="TimeStampingEKUValidator"/>. Set to <see langword="null"/> to apply no
    /// rules beyond chain building.
    /// </remarks>
    public ICertificateValidator? TimeStampCertificateValidator { get; set; } = new TimeStampingEKUValidator();
}