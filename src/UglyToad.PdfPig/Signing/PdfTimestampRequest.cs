namespace UglyToad.PdfPig.Signing;

using System;

/// <summary>
/// Describes an already-created CMS signature which may be post-processed with a timestamp token.
/// </summary>
public sealed class PdfTimestampRequest
{
    /// <summary>
    /// The detached CMS signature produced by <see cref="IPdfSignatureProvider.SignAsync"/>.
    /// </summary>
    public ReadOnlyMemory<byte> CmsSignature { get; }

    /// <summary>
    /// The requested digest algorithm, for example <c>SHA-256</c>.
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
    /// Creates a new <see cref="PdfTimestampRequest"/>.
    /// </summary>
    public PdfTimestampRequest(ReadOnlyMemory<byte> cmsSignature, string digestAlgorithm, string filter, string subFilter, PdfSignatureMetadata metadata)
    {
        CmsSignature = cmsSignature;
        DigestAlgorithm = digestAlgorithm ?? throw new ArgumentNullException(nameof(digestAlgorithm));
        Filter = filter ?? throw new ArgumentNullException(nameof(filter));
        SubFilter = subFilter ?? throw new ArgumentNullException(nameof(subFilter));
        Metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
    }
}