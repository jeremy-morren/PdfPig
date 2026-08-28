namespace UglyToad.PdfPig.Signing;

using System;

/// <summary>
/// Thrown by an <see cref="ICertificateValidator"/> when a certificate does not meet its rules.
/// </summary>
/// <remarks>
/// Verification catches this rather than letting it propagate: the signature is reported with
/// <see cref="PdfSignatureError.CertificateValidationFailed"/> and the exception is carried on
/// <see cref="PdfSignatureVerificationResult.CertificateValidationException"/>.
/// </remarks>
public class PdfCertificateValidationFailedException : Exception
{
    /// <summary>
    /// Creates a new <see cref="PdfCertificateValidationFailedException"/>.
    /// </summary>
    public PdfCertificateValidationFailedException(string message) : base(message)
    {
    }

    /// <summary>
    /// Creates a new <see cref="PdfCertificateValidationFailedException"/>.
    /// </summary>
    public PdfCertificateValidationFailedException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
