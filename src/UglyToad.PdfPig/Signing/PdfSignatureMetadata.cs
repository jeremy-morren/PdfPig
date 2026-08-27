namespace UglyToad.PdfPig.Signing;

/// <summary>
/// Optional metadata written to the PDF signature dictionary.
/// </summary>
public sealed class PdfSignatureMetadata
{
    /// <summary>
    /// An empty metadata instance.
    /// </summary>
    public static PdfSignatureMetadata Empty { get; } = new();

    /// <summary>
    /// The human-readable signing reason.
    /// </summary>
    public string? Reason { get; }

    /// <summary>
    /// The signing location.
    /// </summary>
    public string? Location { get; }

    /// <summary>
    /// Contact information associated with the signer.
    /// </summary>
    public string? ContactInfo { get; }

    /// <summary>
    /// The name of the signer
    /// </summary>
    public string? Name { get; }

    /// <summary>
    /// Creates a new <see cref="PdfSignatureMetadata"/>.
    /// </summary>
    public PdfSignatureMetadata(
        string? reason = null,
        string? location = null,
        string? contactInfo = null,
        string? name = null)
    {
        Reason = reason;
        Location = location;
        ContactInfo = contactInfo;
        Name = name;
    }
}