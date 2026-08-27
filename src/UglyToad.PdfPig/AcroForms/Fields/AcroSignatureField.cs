namespace UglyToad.PdfPig.AcroForms.Fields;

using Core;
using Tokens;

/// <inheritdoc />
/// <summary>
/// A digital signature field.
/// </summary>
public class AcroSignatureField : AcroFieldBase
{
    /// <summary>
    /// The parsed signature dictionary referenced by this field, if the field is signed.
    /// </summary>
    public AcroSignatureValue? SignatureValue { get; }

    /// <summary>
    /// Whether this field currently contains a signature value.
    /// </summary>
    public bool IsSigned => SignatureValue != null;

    /// <inheritdoc />
    /// <summary>
    /// Create a new <see cref="T:UglyToad.PdfPig.AcroForms.Fields.AcroSignatureField" />.
    /// </summary>
    public AcroSignatureField(
        DictionaryToken dictionary,
        string fieldType,
        uint fieldFlags,
        AcroFieldCommonInformation information,
        int? pageNumber,
        PdfRectangle? bounds,
        AcroSignatureValue? signatureValue = null) :
        base(dictionary, fieldType, fieldFlags, AcroFieldType.Signature, information, pageNumber, bounds)
    {
        SignatureValue = signatureValue;
    }
}