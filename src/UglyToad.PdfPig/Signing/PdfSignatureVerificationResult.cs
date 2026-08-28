using System.Security.Cryptography.X509Certificates;

namespace UglyToad.PdfPig.Signing;

/// <summary>
/// Represents the verification outcome for a PDF signature or one of its attached timestamps.
/// </summary>
public sealed class PdfSignatureVerificationResult
{
    /// <summary>
    /// Gets a value indicating whether the signature or timestamp was valid.
    /// </summary>
    public bool IsValid => ValidationError is null;

    /// <summary>
    /// Gets the validation error when the result is invalid.
    /// </summary>
    public PdfSignatureError? ValidationError { get; }

    /// <summary>
    /// Gets the fully qualified AcroForm field name for the signature field, if known.
    /// </summary>
    public string? FieldName { get; }

    /// <summary>
    /// Gets a human-readable description of the validation result.
    /// </summary>
    public string? Message { get; }

    /// <summary>
    /// Gets the certificate associated with the result, if one could be resolved.
    /// </summary>
    public X509Certificate2? Certificate { get; }

    /// <summary>
    /// Gets the signing time extracted from the CMS signature, if present.
    /// </summary>
    public DateTimeOffset? SigningTime { get; }

    /// <summary>
    /// Gets the RFC 3161 timestamp time, if present.
    /// </summary>
    public DateTimeOffset? TimeStampTime { get; }

    /// <summary>
    /// Gets a value indicating whether the signature byte range covers the entire current document revision,
    /// excluding only the embedded signature contents span.
    /// </summary>
    public bool CoversEntireDocument { get; }

    /// <summary>
    /// Gets the encoding of the signature that was found, taken from its <c>/SubFilter</c> entry.
    /// </summary>
    public PdfSignatureSubFilter SubFilter { get; }

    /// <summary>
    /// Gets the exception thrown by the configured <see cref="ICertificateValidator"/>, when
    /// <see cref="ValidationError"/> is <see cref="PdfSignatureError.CertificateValidationFailed"/>.
    /// </summary>
    public PdfCertificateValidationFailedException? CertificateValidationException { get; }

    /// <summary>
    /// Creates a new <see cref="PdfSignatureVerificationResult"/>.
    /// </summary>
    /// <param name="validationError">The validation error, or <see langword="null"/> when valid.</param>
    /// <param name="fieldName">The fully qualified field name, if known.</param>
    /// <param name="message">A human-readable description of the outcome.</param>
    /// <param name="certificate">The certificate associated with the result, if available.</param>
    /// <param name="signingTime">The CMS signing time, if available.</param>
    /// <param name="timeStampTime">The RFC 3161 timestamp time, if available.</param>
    /// <param name="coversEntireDocument">Whether the signature byte range covers the entire current document revision.</param>
    /// <param name="subFilter">The encoding of the signature that was found.</param>
    /// <param name="certificateValidationException">The exception thrown by the certificate validator, if any.</param>
    public PdfSignatureVerificationResult(
        PdfSignatureError? validationError,
        string? fieldName,
        string? message,
        X509Certificate2? certificate,
        DateTimeOffset? signingTime,
        DateTimeOffset? timeStampTime,
        bool coversEntireDocument,
        PdfSignatureSubFilter subFilter = PdfSignatureSubFilter.Unknown,
        PdfCertificateValidationFailedException? certificateValidationException = null)
    {
        ValidationError = validationError;
        FieldName = fieldName;
        Message = message;
        Certificate = certificate;
        SigningTime = signingTime;
        TimeStampTime = timeStampTime;
        CoversEntireDocument = coversEntireDocument;
        SubFilter = subFilter;
        CertificateValidationException = certificateValidationException;
    }

    /// <summary>
    /// Throws an <see cref="InvalidOperationException"/> when the result is invalid.
    /// </summary>
    public void ThrowIfInvalid()
    {
        if (!IsValid)
        {
            throw new InvalidOperationException(Message ?? $"The PDF signature '{FieldName ?? "<unnamed>"}' is invalid: {ValidationError}.");
        }
    }
}