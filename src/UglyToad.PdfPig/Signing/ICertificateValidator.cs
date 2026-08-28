namespace UglyToad.PdfPig.Signing;

using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Applies caller-defined rules to a certificate found in a PDF signature, beyond the chain building
/// and revocation checking described by <see cref="PdfCertificateTrustOptions"/>.
/// </summary>
/// <remarks>
/// Implement this to decide what a certificate must look like to be acceptable. There is no single
/// answer PdfPig could hard-code: certificates issued for document signing under the Adobe conventions
/// are identified by an extended key usage, while European qualified certificates often carry no
/// extended key usage at all and declare their purpose through QCStatements instead.
/// </remarks>
public interface ICertificateValidator
{
    /// <summary>
    /// Checks the certificate, returning normally when it is acceptable.
    /// </summary>
    /// <param name="certificate">The certificate to check.</param>
    /// <param name="subFilter">
    /// The encoding of the signature the certificate was found in, so that rules can differ by
    /// signature type. When checking a timestamp authority's certificate this is the encoding of the
    /// signature the timestamp is attached to.
    /// </param>
    /// <exception cref="PdfCertificateValidationFailedException">
    /// Thrown when the certificate is not acceptable. The exception is reported on the verification
    /// result, so its message should say what was expected and what was found.
    /// </exception>
    void ValidateCertificate(X509Certificate2 certificate, PdfSignatureSubFilter subFilter);
}
