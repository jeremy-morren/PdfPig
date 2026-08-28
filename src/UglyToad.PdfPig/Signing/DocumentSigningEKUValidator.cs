namespace UglyToad.PdfPig.Signing;

using System.Security.Cryptography;

/// <summary>
/// Requires a signing certificate to declare an extended key usage that Adobe accepts for document
/// signing. This is the default <see cref="ICertificateValidator"/> for signatures.
/// </summary>
/// <remarks>
/// <para>
/// There is no single identifier the ecosystem settled on. RFC 9336 defines <c>id-kp-documentSigning</c>,
/// Adobe minted its own, and certificates issued under the Adobe Approved Trust List and Certified
/// Document Services conventionally carry <c>emailProtection</c> — the U.S. Government Publishing Office
/// signs with such a certificate.
/// </para>
/// <para>
/// European qualified certificates commonly declare no extended key usage at all, conveying their
/// purpose through QCStatements instead, and are therefore rejected by this validator. Supply a
/// different <see cref="ICertificateValidator"/> to accept them.
/// </para>
/// </remarks>
public sealed class DocumentSigningEKUValidator : EnhancedKeyUsageValidator
{
    /// <summary>
    /// <c>id-kp-documentSigning</c>, defined by RFC 9336.
    /// </summary>
    public const string DocumentSigningOid = "1.3.6.1.5.5.7.3.36";

    /// <summary>
    /// Adobe's authentic documents / PDF signing usage.
    /// </summary>
    public const string AdobeAuthenticDocumentsOid = "1.2.840.113583.1.1.5";

    /// <summary>
    /// <c>emailProtection</c>, as used by Adobe Approved Trust List and Certified Document Services
    /// signing certificates.
    /// </summary>
    public const string EmailProtectionOid = "1.3.6.1.5.5.7.3.4";

    /// <summary>
    /// <c>codeSigning</c>.
    /// </summary>
    public const string CodeSigningOid = "1.3.6.1.5.5.7.3.3";

    /// <summary>
    /// <c>anyExtendedKeyUsage</c>, which places no restriction on the certificate.
    /// </summary>
    public const string AnyExtendedKeyUsageOid = "2.5.29.37.0";

    /// <summary>
    /// Creates a new <see cref="DocumentSigningEKUValidator"/>.
    /// </summary>
    public DocumentSigningEKUValidator() : base(
        new Oid(DocumentSigningOid, "Document Signing"),
        new Oid(AdobeAuthenticDocumentsOid, "Adobe Authentic Documents"),
        new Oid(EmailProtectionOid, "Secure Email"),
        new Oid(CodeSigningOid, "Code Signing"),
        new Oid(AnyExtendedKeyUsageOid, "Any Purpose"))
    {
    }
}
