using System.Security.Cryptography;
using iText.Commons.Digest;
using iText.Kernel.Crypto;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;

namespace UglyToad.PdfPig.SigningTest;

internal sealed class PdfScenarioWriter
{
    private const string ByteRangeName = "/ByteRange";

    private readonly string sourcePdf;

    public PdfScenarioWriter(string sourcePdf)
    {
        this.sourcePdf = sourcePdf;
    }

    public void CreateSignedPdf(string outputPath, CertificateMaterial signer, string description)
    {
        SignDetached(sourcePdf, outputPath, GetFieldNameBase(outputPath) + "_sig1", signer, description, null);
    }

    public void CreateSignedAndTimestampedPdf(
        string outputPath,
        CertificateMaterial signer,
        CertificateMaterial tsaCertificate,
        string description)
    {
        SignDetached(sourcePdf, outputPath, GetFieldNameBase(outputPath) + "_sig1", signer, description, new LocalTsaClient(tsaCertificate));
    }

    public void CreateSignedWithInvalidTimestampCmsPdf(
        string outputPath,
        CertificateMaterial signer,
        CertificateMaterial tsaCertificate,
        string description)
    {
        SignDetached(sourcePdf, outputPath, GetFieldNameBase(outputPath) + "_sig1", signer, description, new MismatchedTsaClient(tsaCertificate));
    }

    public void CreateInvalidCmsPdf(string outputPath, string description)
    {
        SignExternalContainer(sourcePdf, outputPath, GetFieldNameBase(outputPath) + "_sig1", description, new InvalidCmsSignatureContainer());
    }

    public void CreateSignedPdfWithMissingByteRange(string outputPath, CertificateMaterial signer, string description)
    {
        SignDetached(sourcePdf, outputPath, GetFieldNameBase(outputPath) + "_sig1", signer, description, null);
        RenameByteRangeKey(outputPath);
    }

    public void CreateSignedPdfWithInvalidByteRange(string outputPath, CertificateMaterial signer, string description)
    {
        SignDetached(sourcePdf, outputPath, GetFieldNameBase(outputPath) + "_sig1", signer, description, null);
        ReplaceByteRangeArray(outputPath, "[0 1 0 0]");
    }

    public void CreatePdfWithMultipleInvalidSignatures(
        string outputPath,
        IReadOnlyList<InvalidSignatureDescriptor> invalidSignatures,
        string description)
    {
        if (invalidSignatures.Count == 0)
        {
            throw new ArgumentException("At least one invalid signature descriptor is required.", nameof(invalidSignatures));
        }

        CreateMultiSignaturePdf(outputPath, description, invalidSignatures.Cast<SignatureOperation>().ToArray());
    }

    public void CreatePdfWithValidAndInvalidSignatures(
        string outputPath,
        SignatureOperation validSignature,
        IReadOnlyList<InvalidSignatureDescriptor> invalidSignatures,
        string description)
    {
        if (invalidSignatures.Count == 0)
        {
            throw new ArgumentException("At least one invalid signature descriptor is required.", nameof(invalidSignatures));
        }

        var operations = new List<SignatureOperation> { validSignature };
        operations.AddRange(invalidSignatures);
        CreateMultiSignaturePdf(outputPath, description, operations);
    }

    public void CreatePdfWithMultipleValidSignatures(
        string outputPath,
        IReadOnlyList<ValidSignatureDescriptor> validSignatures,
        string description)
    {
        if (validSignatures.Count == 0)
        {
            throw new ArgumentException("At least one valid signature descriptor is required.", nameof(validSignatures));
        }

        CreateMultiSignaturePdf(outputPath, description, validSignatures.Cast<SignatureOperation>().ToArray());
    }

    private void CreateMultiSignaturePdf(string outputPath, string description, IReadOnlyList<SignatureOperation> operations)
    {
        var workingInput = sourcePdf;
        var tempFiles = new List<string>();
        var fieldNameBase = GetFieldNameBase(outputPath);

        try
        {
            for (var index = 0; index < operations.Count; index++)
            {
                var operation = operations[index];
                var isLast = index == operations.Count - 1;
                var currentOutput = isLast
                    ? outputPath
                    : System.IO.Path.Combine(System.IO.Path.GetDirectoryName(outputPath)!, System.IO.Path.GetFileNameWithoutExtension(outputPath) + $".stage{index + 1}.pdf");

                if (!isLast)
                {
                    tempFiles.Add(currentOutput);
                }

                var fieldName = $"{fieldNameBase}_sig{index + 1}";
                var stepDescription = $"{description} Signature {index + 1}: {operation.Description}";

                switch (operation)
                {
                    case ValidSignatureDescriptor valid when valid.TsaCertificate is null:
                        SignDetached(workingInput, currentOutput, fieldName, valid.Signer, stepDescription, null);
                        break;
                    case ValidSignatureDescriptor valid:
                        SignDetached(workingInput, currentOutput, fieldName, valid.Signer, stepDescription, new LocalTsaClient(valid.TsaCertificate!));
                        break;
                    case InvalidSignatureDescriptor invalid when invalid.Kind == InvalidSignatureKind.InvalidCms:
                        SignExternalContainer(workingInput, currentOutput, fieldName, stepDescription, new InvalidCmsSignatureContainer());
                        break;
                    case InvalidSignatureDescriptor invalid when invalid.Kind == InvalidSignatureKind.InvalidTimestampCms:
                        SignDetached(workingInput, currentOutput, fieldName, invalid.Signer, stepDescription, new MismatchedTsaClient(invalid.TsaCertificate!));
                        break;
                    case InvalidSignatureDescriptor invalid:
                        SignDetached(workingInput, currentOutput, fieldName, invalid.Signer, stepDescription, null);
                        break;
                    default:
                        throw new NotSupportedException($"Unsupported signature operation type: {operation.GetType().Name}.");
                }

                workingInput = currentOutput;
            }
        }
        finally
        {
            foreach (var tempFile in tempFiles)
            {
                if (File.Exists(tempFile))
                {
                    File.Delete(tempFile);
                }
            }
        }
    }

    private static string GetFieldNameBase(string outputPath)
    {
        return SanitizeFieldName(System.IO.Path.GetFileNameWithoutExtension(outputPath));
    }

    private static SignerProperties CreateSignerProperties(string fieldName, string description)
    {
        return new SignerProperties()
            .SetFieldName(fieldName)
            .SetReason(description)
            .SetLocation("UglyToad.PdfPig.SigningTest")
            .SetPageNumber(1)
            .SetPageRect(new Rectangle(36, 36, 0, 0));
    }

    private static void SignDetached(
        string inputPath,
        string outputPath,
        string fieldName,
        CertificateMaterial signer,
        string description,
        ITSAClient? tsaClient)
    {
        using var reader = new PdfReader(inputPath);
        using var output = File.Create(outputPath);

        var pdfSigner = new PdfSigner(reader, output, new StampingProperties().UseAppendMode());
        pdfSigner.SetSignerProperties(CreateSignerProperties(fieldName, description));

        pdfSigner.SignDetached(
            new BouncyCastleDigest(),
            new PrivateKeySignature(signer.GetITextPrivateKey(), DigestAlgorithms.SHA256),
            signer.GetITextChain(),
            null,
            null,
            tsaClient,
            0,
            PdfSigner.CryptoStandard.CMS);
    }

    private static void SignExternalContainer(
        string inputPath,
        string outputPath,
        string fieldName,
        string description,
        IExternalSignatureContainer signatureContainer)
    {
        using var reader = new PdfReader(inputPath);
        using var output = File.Create(outputPath);

        var pdfSigner = new PdfSigner(reader, output, new StampingProperties().UseAppendMode());
        pdfSigner.SetSignerProperties(CreateSignerProperties(fieldName, description));
        pdfSigner.SignExternalContainer(signatureContainer, 2048);
    }

    private static string SanitizeFieldName(string value)
    {
        var builder = new System.Text.StringBuilder(value.Length);
        foreach (var character in value)
        {
            builder.Append(char.IsLetterOrDigit(character) ? character : '_');
        }

        return builder.Length == 0 ? "SignatureField" : builder.ToString();
    }

    private static void RenameByteRangeKey(string pdfPath)
    {
        ReplaceFirstOccurrenceInPlace(pdfPath, ByteRangeName, "/ByteRangX");
    }

    private static void ReplaceByteRangeArray(string pdfPath, string replacementArray)
    {
        var pdfBytes = File.ReadAllBytes(pdfPath);
        var pdfText = System.Text.Encoding.Latin1.GetString(pdfBytes);

        var byteRangeNameIndex = pdfText.IndexOf(ByteRangeName, StringComparison.Ordinal);
        if (byteRangeNameIndex < 0)
        {
            throw new InvalidOperationException($"Could not find {ByteRangeName} in generated PDF: {pdfPath}.");
        }

        var arrayStartIndex = pdfText.IndexOf('[', byteRangeNameIndex);
        var arrayEndIndex = pdfText.IndexOf(']', arrayStartIndex);
        if (arrayStartIndex < 0 || arrayEndIndex < 0 || arrayEndIndex < arrayStartIndex)
        {
            throw new InvalidOperationException($"Could not find a {ByteRangeName} array in generated PDF: {pdfPath}.");
        }

        var existingArrayLength = arrayEndIndex - arrayStartIndex + 1;
        if (replacementArray.Length > existingArrayLength)
        {
            throw new InvalidOperationException($"Replacement byte range '{replacementArray}' is longer than the original /ByteRange array in {pdfPath}.");
        }

        var paddedReplacement = replacementArray.PadRight(existingArrayLength, ' ');
        var replacementBytes = System.Text.Encoding.Latin1.GetBytes(paddedReplacement);
        Buffer.BlockCopy(replacementBytes, 0, pdfBytes, arrayStartIndex, replacementBytes.Length);

        File.WriteAllBytes(pdfPath, pdfBytes);
    }

    private static void ReplaceFirstOccurrenceInPlace(string pdfPath, string oldValue, string newValue)
    {
        if (newValue.Length != oldValue.Length)
        {
            throw new ArgumentException("In-place PDF replacements must preserve length.", nameof(newValue));
        }

        var pdfBytes = File.ReadAllBytes(pdfPath);
        var pdfText = System.Text.Encoding.Latin1.GetString(pdfBytes);
        var startIndex = pdfText.IndexOf(oldValue, StringComparison.Ordinal);
        if (startIndex < 0)
        {
            throw new InvalidOperationException($"Could not find '{oldValue}' in generated PDF: {pdfPath}.");
        }

        var replacementBytes = System.Text.Encoding.Latin1.GetBytes(newValue);
        Buffer.BlockCopy(replacementBytes, 0, pdfBytes, startIndex, replacementBytes.Length);

        File.WriteAllBytes(pdfPath, pdfBytes);
    }

    private sealed class LocalTsaClient : ITSAClient
    {
        private readonly CertificateMaterial tsaCertificate;
        private readonly BouncyCastleDigest digest = new();

        public LocalTsaClient(CertificateMaterial tsaCertificate)
        {
            this.tsaCertificate = tsaCertificate;
        }

        public int GetTokenSizeEstimate() => 8192;

        public IMessageDigest GetMessageDigest() => digest.GetMessageDigest(DigestAlgorithms.SHA256);

        public byte[] GetTimeStampToken(byte[] imprint)
        {
            var requestGenerator = new TimeStampRequestGenerator();
            requestGenerator.SetCertReq(true);

            var nonce = CreateNonce();
            var request = requestGenerator.Generate(TspAlgorithms.Sha256, imprint, nonce);
            var generator = new TimeStampTokenGenerator(
                tsaCertificate.GetBouncyCastlePrivateKey(),
                tsaCertificate.GetBouncyCastleCertificate(),
                TspAlgorithms.Sha256,
                "1.3.6.1.4.1.55555.1.1");
            generator.SetCertificates(tsaCertificate.GetBouncyCastleCertificateStore());

            var token = generator.Generate(request, CreateSerialNumber(), DateTime.UtcNow);
            return token.GetEncoded();
        }

        internal static BigInteger CreateSerialNumber()
        {
            Span<byte> serialBytes = stackalloc byte[16];
            RandomNumberGenerator.Fill(serialBytes);
            serialBytes[0] &= 0x7F;
            return new BigInteger(1, serialBytes.ToArray());
        }

        internal static BigInteger CreateNonce()
        {
            Span<byte> nonceBytes = stackalloc byte[16];
            RandomNumberGenerator.Fill(nonceBytes);
            nonceBytes[0] &= 0x7F;
            return new BigInteger(1, nonceBytes.ToArray());
        }
    }

    private sealed class MismatchedTsaClient : ITSAClient
    {
        private readonly CertificateMaterial tsaCertificate;
        private readonly BouncyCastleDigest digest = new();

        public MismatchedTsaClient(CertificateMaterial tsaCertificate)
        {
            this.tsaCertificate = tsaCertificate;
        }

        public int GetTokenSizeEstimate() => 1024;

        public IMessageDigest GetMessageDigest() => digest.GetMessageDigest(DigestAlgorithms.SHA256);

        public byte[] GetTimeStampToken(byte[] imprint)
        {
            var wrongImprint = new byte[imprint.Length];
            RandomNumberGenerator.Fill(wrongImprint);

            var requestGenerator = new TimeStampRequestGenerator();
            requestGenerator.SetCertReq(true);

            var request = requestGenerator.Generate(TspAlgorithms.Sha256, wrongImprint, LocalTsaClient.CreateNonce());
            var generator = new TimeStampTokenGenerator(
                tsaCertificate.GetBouncyCastlePrivateKey(),
                tsaCertificate.GetBouncyCastleCertificate(),
                TspAlgorithms.Sha256,
                "1.3.6.1.4.1.55555.1.1");
            generator.SetCertificates(tsaCertificate.GetBouncyCastleCertificateStore());

            var token = generator.Generate(request, LocalTsaClient.CreateSerialNumber(), DateTime.UtcNow);
            return token.GetEncoded();
        }
    }

    private sealed class InvalidCmsSignatureContainer : IExternalSignatureContainer
    {
        private static readonly byte[] InvalidCmsBytes = System.Text.Encoding.ASCII.GetBytes("not-a-valid-cms-payload");

        public byte[] Sign(Stream data) => InvalidCmsBytes;

        public void ModifySigningDictionary(PdfDictionary signDictionary)
        {
            signDictionary.Put(PdfName.Filter, PdfName.Adobe_PPKLite);
            signDictionary.Put(PdfName.SubFilter, PdfName.Adbe_pkcs7_detached);
        }
    }
}

internal abstract record SignatureOperation(string Description);

internal sealed record ValidSignatureDescriptor(
    CertificateMaterial Signer,
    string Description,
    CertificateMaterial? TsaCertificate = null) : SignatureOperation(Description);

internal sealed record InvalidSignatureDescriptor(
    CertificateMaterial Signer,
    string Description,
    InvalidSignatureKind Kind = InvalidSignatureKind.InvalidCertificate,
    CertificateMaterial? TsaCertificate = null) : SignatureOperation(Description);

internal enum InvalidSignatureKind
{
    InvalidCertificate,
    InvalidTimestampCms,
    InvalidCms
}
