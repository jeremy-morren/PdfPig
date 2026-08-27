namespace UglyToad.PdfPig.Signing;

using Core;

/// <summary>
/// Controls where a visible signature field widget is placed.
/// </summary>
public sealed class PdfSignatureFieldPlacement
{
    /// <summary>
    /// The one-based page number for the signature widget.
    /// </summary>
    public int PageNumber { get; }

    /// <summary>
    /// The placement rectangle for the signature widget.
    /// </summary>
    public PdfRectangle Bounds { get; }

    /// <summary>
    /// Creates a new <see cref="PdfSignatureFieldPlacement"/>.
    /// </summary>
    public PdfSignatureFieldPlacement(int pageNumber, PdfRectangle bounds)
    {
        PageNumber = pageNumber;
        Bounds = bounds;
    }

    /// <summary>
    /// The default signature placement (an invisible box on page 1)
    /// </summary>
    public static readonly PdfSignatureFieldPlacement Default =
        new(1, new PdfRectangle(0, 0, 0, 0));
}