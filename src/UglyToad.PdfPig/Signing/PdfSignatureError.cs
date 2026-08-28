namespace UglyToad.PdfPig.Signing;

/// <summary>
/// Identifies a specific validation failure for a PDF signature or an attached timestamp token.
/// </summary>
public enum PdfSignatureError
{
    /// <summary>
    /// The signature field did not contain a usable signature dictionary.
    /// </summary>
    SignatureDictionaryMissing,

    /// <summary>
    /// The signature used a PDF subfilter that PdfPig does not verify.
    /// </summary>
    UnsupportedSubFilter,

    /// <summary>
    /// The signature dictionary did not contain a <c>/ByteRange</c> entry.
    /// </summary>
    ByteRangeMissing,

    /// <summary>
    /// The <c>/ByteRange</c> entry was malformed or referred to invalid spans in the document.
    /// </summary>
    ByteRangeInvalid,

    /// <summary>
    /// The signature dictionary did not contain a <c>/Contents</c> entry.
    /// </summary>
    ContentsMissing,

    /// <summary>
    /// The <c>/Contents</c> entry was malformed or could not be converted to CMS bytes.
    /// </summary>
    ContentsInvalid,

    /// <summary>
    /// The configured <see cref="ICertificateValidator"/> rejected the certificate. The exception it
    /// threw is available on <see cref="PdfSignatureVerificationResult.CertificateValidationException"/>.
    /// </summary>
    CertificateValidationFailed,

    /// <summary>
    /// The CMS payload could not be decoded or was structurally invalid.
    /// </summary>
    CmsInvalid,

    /// <summary>
    /// The detached CMS signature did not validate against the signed PDF byte ranges.
    /// </summary>
    SignatureMismatch,

    /// <summary>
    /// The signature itself is cryptographically sound, but the document contains bytes beyond the
    /// span it covers and no other signature covers them, so content was appended after signing.
    /// </summary>
    DocumentModifiedAfterSigning,

    /// <summary>
    /// The CMS payload did not contain a usable signing certificate.
    /// </summary>
    SigningCertificateMissing,

    /// <summary>
    /// The signing certificate chain did not build to a trusted root.
    /// </summary>
    SigningCertificateNotTrusted,

    /// <summary>
    /// The signing certificate chain reported a revocation failure.
    /// </summary>
    SigningCertificateRevoked,

    /// <summary>
    /// The signing certificate chain reported an invalid validity period.
    /// </summary>
    SigningCertificateExpired,

    /// <summary>
    /// An attached RFC 3161 timestamp token could not be decoded or was structurally invalid.
    /// </summary>
    TimeStampTokenInvalid,

    /// <summary>
    /// An attached RFC 3161 timestamp token did not match the signature it claims to timestamp.
    /// </summary>
    TimeStampTokenMismatch,

    /// <summary>
    /// The timestamp token did not contain a usable TSA signing certificate.
    /// </summary>
    TimeStampCertificateMissing,

    /// <summary>
    /// The TSA certificate chain did not build to a trusted root.
    /// </summary>
    TimeStampCertificateNotTrusted,

    /// <summary>
    /// The TSA certificate chain reported a revocation failure.
    /// </summary>
    TimeStampCertificateRevoked,

    /// <summary>
    /// The TSA certificate chain reported an invalid validity period.
    /// </summary>
    TimeStampCertificateExpired,

    /// <summary>
    /// The timestamp time was earlier than the signing time recorded in the CMS signature.
    /// </summary>
    TimeStampBeforeSigning,

    /// <summary>
    /// An unexpected validation failure occurred that did not map to a more specific error.
    /// </summary>
    Unknown
}