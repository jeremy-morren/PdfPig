namespace UglyToad.PdfPig.Signing;

/// <summary>
/// Controls how a new PDF signature revision is created.
/// </summary>
public sealed class PdfSignatureOptions
{
    /// <summary>
    /// The AcroForm field name to create or update.
    /// </summary>
    public string FieldName { get; set; } = "Signature1";

    /// <summary>
    /// The reserved size, in bytes, available for the final CMS payload before hex encoding.
    /// </summary>
    public int ReservedContentsLength { get; set; } = 16384;

    /// <summary>
    /// The PDF signature filter name.
    /// </summary>
    public string Filter { get; set; } = "Adobe.PPKLite";

    /// <summary>
    /// The PDF signature subfilter name.
    /// </summary>
    public string SubFilter { get; set; } = "adbe.pkcs7.detached";

    /// <summary>
    /// The digest algorithm requested from the signature provider.
    /// </summary>
    public string DigestAlgorithm { get; set; } = "SHA-256";

    /// <summary>
    /// Whether the generated CMS signature should be post-processed with <see cref="IPdfSignatureProvider.TimestampAsync"/>.
    /// </summary>
    public bool AddTimestamp { get; set; }

    /// <summary>
    /// Additional signature dictionary metadata.
    /// </summary>
    public PdfSignatureMetadata Metadata { get; set; } = PdfSignatureMetadata.Empty;

    /// <summary>
    /// Optional visible widget placement. When omitted, an invisible zero-area widget is created on the first page.
    /// </summary>
    public PdfSignatureFieldPlacement? Placement { get; set; }
}