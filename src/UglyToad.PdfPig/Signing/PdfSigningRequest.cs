namespace UglyToad.PdfPig.Signing;

using System;

/// <summary>
/// Describes the exact PDF byte ranges that must be signed by an <see cref="IPdfSignatureProvider"/>.
/// </summary>
public sealed class PdfSigningRequest
{
    /// <summary>
    /// The concatenated byte ranges to sign.
    /// </summary>
    public byte[] ContentToSign { get; }

    /// <summary>
    /// The requested digest algorithm. Possible values are <c>SHA-256</c>, <c>SHA-384</c>, <c>SHA-512</c>
    /// </summary>
    public string DigestAlgorithm { get; }

    /// <summary>
    /// The PDF signature filter name.
    /// </summary>
    public string Filter { get; }

    /// <summary>
    /// The PDF signature subfilter name.
    /// </summary>
    public string SubFilter { get; }

    /// <summary>
    /// Additional signature dictionary metadata.
    /// </summary>
    public PdfSignatureMetadata Metadata { get; }

    /// <summary>
    /// The reserved size, in bytes, available for the final CMS payload before hex encoding.
    /// </summary>
    public int ReservedContentsLength { get; }

    /// <summary>
    /// Creates a new <see cref="PdfSigningRequest"/>.
    /// </summary>
    public PdfSigningRequest(
        byte[] contentToSign,
        string digestAlgorithm,
        string filter,
        string subFilter,
        PdfSignatureMetadata metadata, int reservedContentsLength)
    {
        ContentToSign = contentToSign;
        DigestAlgorithm = digestAlgorithm ?? throw new ArgumentNullException(nameof(digestAlgorithm));
        Filter = filter ?? throw new ArgumentNullException(nameof(filter));
        SubFilter = subFilter ?? throw new ArgumentNullException(nameof(subFilter));
        Metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
        ReservedContentsLength = reservedContentsLength;
    }
}