namespace UglyToad.PdfPig.Signing;

/// <summary>
/// The encoding of a PDF signature, taken from the <c>/SubFilter</c> entry of its signature dictionary.
/// </summary>
public enum PdfSignatureSubFilter
{
    /// <summary>
    /// The signature declares no <c>/SubFilter</c>, or one PdfPig does not recognise.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// <c>adbe.pkcs7.detached</c>: a detached CMS signature over the byte ranges. Verified by PdfPig.
    /// </summary>
    Pkcs7Detached,

    /// <summary>
    /// <c>ETSI.CAdES.detached</c>: PAdES. Structurally the same detached CMS signature, additionally
    /// required to bind the signing certificate through an ESS signing-certificate signed attribute.
    /// Verified by PdfPig.
    /// </summary>
    CAdESDetached,

    /// <summary>
    /// <c>adbe.pkcs7.sha1</c>: a CMS signature whose encapsulated content is the SHA-1 digest of the
    /// byte ranges. Legacy, and not verified by PdfPig.
    /// </summary>
    Pkcs7Sha1,

    /// <summary>
    /// <c>adbe.x509.rsa_sha1</c>: a bare PKCS#1 signature with the certificate in <c>/Cert</c>, rather
    /// than a CMS payload. Obsolete, and not verified by PdfPig.
    /// </summary>
    X509RsaSha1,

    /// <summary>
    /// <c>ETSI.RFC3161</c>: a document timestamp rather than a signature, holding an RFC 3161 token
    /// directly in <c>/Contents</c>. Not verified by PdfPig.
    /// </summary>
    DocumentTimeStamp
}
