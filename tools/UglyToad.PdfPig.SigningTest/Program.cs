using System.Globalization;
using iText.Forms;
using iText.Forms.Fields;
using iText.Kernel.Pdf;

namespace UglyToad.PdfPig.SigningTest;

internal static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length != 2)
        {
            Console.Error.WriteLine("Usage: UglyToad.PdfPig.SigningTest <source-pdf> <output-dir>");
            return 1;
        }

        var sourcePdf = Path.GetFullPath(args[0]);
        var outputDirectory = Path.GetFullPath(args[1]);

        if (!File.Exists(sourcePdf))
        {
            Console.Error.WriteLine(FormattableString.Invariant($"Source PDF not found: {sourcePdf}"));
            return 2;
        }

        if (TryGetExistingSignatureFields(sourcePdf, out var signatureFields))
        {
            Console.Error.WriteLine(FormattableString.Invariant($"Source PDF must not already contain signature fields. Found: {string.Join(", ", signatureFields)}"));
            return 3;
        }

        SigningScenarioRunner.Run(sourcePdf, outputDirectory);
        Console.WriteLine(FormattableString.Invariant($"Generated signing test output in: {outputDirectory}"));
        return 0;
    }

    // Reject source PDFs that already contain signature fields so each generated output starts from an unconfounded baseline.
    private static bool TryGetExistingSignatureFields(string sourcePdf, out string[] signatureFields)
    {
        using var reader = new PdfReader(sourcePdf);
        using var pdfDocument = new PdfDocument(reader);

        var acroForm = PdfAcroForm.GetAcroForm(pdfDocument, false);
        if (acroForm is null)
        {
            signatureFields = [];
            return false;
        }

        signatureFields = acroForm
            .GetAllFormFields()
            .Where(x => x.Value is PdfSignatureFormField)
            .Select(x => x.Key)
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToArray();

        return signatureFields.Length > 0;
    }
}
