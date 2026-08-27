namespace UglyToad.PdfPig.AcroForms.Fields;

using Core;
using Signing;
using Tokens;

/// <summary>
/// A parsed read-only view of a signature dictionary referenced by an <see cref="AcroSignatureField"/>.
/// </summary>
public class AcroSignatureValue
{
    /// <summary>
    /// The raw signature dictionary.
    /// </summary>
    public DictionaryToken Dictionary { get; }

    /// <summary>
    /// The indirect reference for the signature dictionary, if it was defined as an indirect object.
    /// </summary>
    public IndirectReference? Reference { get; }

    /// <summary>
    /// The signature handler filter name.
    /// </summary>
    public string? Filter { get; }

    /// <summary>
    /// The signature encoding subfilter name.
    /// </summary>
    public string? SubFilter { get; }

    /// <summary>
    /// The byte ranges covered by the signature.
    /// </summary>
    public IReadOnlyList<long> ByteRange { get; }

    /// <summary>
    /// The raw embedded CMS signature contents.
    /// </summary>
    public ReadOnlyMemory<byte> Contents { get; }

    internal int ContentsFieldValueLength { get; }

    /// <summary>
    /// The signature metadata
    /// </summary>
    public PdfSignatureMetadata Metadata { get; }

    /// <summary>
    /// The signing time from the PDF signature dictionary, if it could be parsed.
    /// </summary>
    public DateTimeOffset? ModifiedDate { get; }

    /// <summary>
    /// Create a new <see cref="AcroSignatureValue"/>.
    /// </summary>
    public AcroSignatureValue(
        DictionaryToken dictionary,
        IndirectReference? reference,
        string? filter,
        string? subFilter,
        IReadOnlyList<long> byteRange,
        ReadOnlyMemory<byte> contents,
        int contentsFieldValueLength,
        PdfSignatureMetadata metadata,
        DateTimeOffset? modifiedDate)
    {
        Dictionary = dictionary ?? throw new ArgumentNullException(nameof(dictionary));
        Reference = reference;
        Filter = filter;
        SubFilter = subFilter;
        ByteRange = byteRange;
        Contents = contents;
        ContentsFieldValueLength = contentsFieldValueLength;
        Metadata = metadata;
        ModifiedDate = modifiedDate;
    }
}