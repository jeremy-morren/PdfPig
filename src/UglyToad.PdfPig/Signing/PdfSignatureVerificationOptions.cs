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
}