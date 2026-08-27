namespace UglyToad.PdfPig.Signing;

using System.Collections.Generic;
using Core;
using Tokens;

internal sealed class PdfDocumentSigningContext
{
    public IndirectReference RootReference { get; }

    public IndirectReference? InformationReference { get; }

    public IReadOnlyList<IDataToken<string>> FileIdentifier { get; }

    public long PreviousCrossReferenceOffset { get; }

    public int MaxObjectNumber { get; }

    public PdfDocumentSigningContext(
        IndirectReference rootReference,
        IndirectReference? informationReference,
        IReadOnlyList<IDataToken<string>> fileIdentifier,
        long previousCrossReferenceOffset,
        int maxObjectNumber)
    {
        RootReference = rootReference;
        InformationReference = informationReference;
        FileIdentifier = fileIdentifier;
        PreviousCrossReferenceOffset = previousCrossReferenceOffset;
        MaxObjectNumber = maxObjectNumber;
    }
}