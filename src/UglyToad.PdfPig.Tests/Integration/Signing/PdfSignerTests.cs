using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using UglyToad.PdfPig.AcroForms;
using UglyToad.PdfPig.AcroForms.Fields;
using UglyToad.PdfPig.Content;
using UglyToad.PdfPig.Core;
using UglyToad.PdfPig.Fonts.Standard14Fonts;
using UglyToad.PdfPig.Signing;
using UglyToad.PdfPig.Writer;

namespace UglyToad.PdfPig.Tests.Integration.Signing;

public class PdfSignerTests
{
    [Fact]
    public async Task SignAsyncCreatesAValidRsaSignatureOverTheCurrentRevision()
    {
        using var certificate = CreateSelfSignedRsaCertificate();
        var sourceBytes = CreateUnsignedPdf();

        using var document = PdfDocument.Open(sourceBytes);
        using var output = new MemoryStream();

        await PdfSigner.SignAsync(
            document,
            output,
            new CmsDetachedSignatureProvider(certificate),
            new PdfSignatureOptions
            {
                FieldName = "Signature1",
                Placement = new PdfSignatureFieldPlacement(1, new PdfRectangle(40, 40, 200, 90)),
                Metadata = new PdfSignatureMetadata(reason: "RSA test signature", location: "Unit test")
            });

        var signedBytes = output.ToArray();

        using var signedDocument = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var result = Assert.Single(signedDocument.GetSignatures(CreateVerificationOptions(certificate))!);
        result.ThrowIfInvalid();
        Assert.True(result.CoversEntireDocument);

        Assert.True(signedDocument.TryGetForm(out var form));
        var signatureField = Assert.Single(form.GetFields().OfType<AcroSignatureField>());
        Assert.Equal("Signature1", signatureField.Information.FullyQualifiedName);
        Assert.True(signatureField.IsSigned);
        Assert.NotNull(signatureField.SignatureValue);
        Assert.Equal(signedBytes.Length, signatureField.SignatureValue!.ByteRange[2] + signatureField.SignatureValue.ByteRange[3]);
    }

    [Fact]
    public async Task SignAsyncCreatesAValidEcdsaSignatureOverTheCurrentRevision()
    {
        using var certificate = CreateSelfSignedEcdsaCertificate();
        var sourceBytes = CreateUnsignedPdf();

        using var document = PdfDocument.Open(sourceBytes);
        using var output = new MemoryStream();

        await PdfSigner.SignAsync(
            document,
            output,
            new CmsDetachedSignatureProvider(certificate),
            new PdfSignatureOptions
            {
                FieldName = "Signature1",
                Metadata = new PdfSignatureMetadata(reason: "ECDSA test signature", location: "A location")
            });

        using var signedDocument = PdfDocument.Open(new MemoryStream(output.ToArray(), writable: false));
        var result = Assert.Single(signedDocument.GetSignatures(CreateVerificationOptions(certificate))!);
        result.ThrowIfInvalid();
    }

    [Fact]
    public async Task SignAsyncTreatsNullTimestampResponseAsNoTimestampNecessary()
    {
        using var certificate = CreateSelfSignedRsaCertificate();
        var sourceBytes = CreateUnsignedPdf();

        using var document = PdfDocument.Open(sourceBytes);
        using var output = new MemoryStream();

        await PdfSigner.SignAsync(
            document,
            output,
            new CmsDetachedSignatureProvider(certificate, returnNullTimestamp: true),
            new PdfSignatureOptions
            {
                FieldName = "Signature1",
                AddTimestamp = true,
                Metadata = new PdfSignatureMetadata(reason: "Null timestamp response")
            });

        using var signedDocument = PdfDocument.Open(new MemoryStream(output.ToArray(), writable: false));
        var signature = Assert.Single(signedDocument.GetSignatures(CreateVerificationOptions(certificate))!);
        signature.ThrowIfInvalid();
        Assert.Null(signedDocument.GetTimestampSignatures(CreateVerificationOptions(certificate)));
    }

    [Fact]
    public async Task SignAsyncAppendsSecondSignatureWithoutRewritingEarlierBytes()
    {
        using var certificate1 = CreateSelfSignedRsaCertificate();
        using var certificate2 = CreateSelfSignedEcdsaCertificate();

        var sourceBytes = CreateUnsignedPdf();
        byte[] firstSignedBytes;

        using (var firstDocument = PdfDocument.Open(sourceBytes))
        using (var firstOutput = new MemoryStream())
        {
            await PdfSigner.SignAsync(
                firstDocument,
                firstOutput,
                new CmsDetachedSignatureProvider(certificate1),
                new PdfSignatureOptions
                {
                    FieldName = "Signature1",
                    Metadata = new PdfSignatureMetadata(reason: "First signature", name: "First name")
                });

            firstSignedBytes = firstOutput.ToArray();
        }

        byte[] secondSignedBytes;

        using (var secondDocumentSource = PdfDocument.Open(new MemoryStream(firstSignedBytes, writable: false)))
        using (var secondOutput = new MemoryStream())
        {
            await PdfSigner.SignAsync(
                secondDocumentSource,
                secondOutput,
                new CmsDetachedSignatureProvider(certificate2),
                new PdfSignatureOptions
                {
                    FieldName = "Signature2",
                    Metadata = new PdfSignatureMetadata(reason: "Second signature", contactInfo: "Second contact info")
                });

            secondSignedBytes = secondOutput.ToArray();
        }

        Assert.True(firstSignedBytes.AsSpan().SequenceEqual(secondSignedBytes.AsSpan(0, firstSignedBytes.Length)));

        using var twiceSignedDocument = PdfDocument.Open(new MemoryStream(secondSignedBytes, writable: false));
        var results = twiceSignedDocument.GetSignatures(CreateVerificationOptions(certificate1, certificate2))!;
        Assert.Equal(2, results.Count);
        Assert.All(results, x => x.ThrowIfInvalid());
        Assert.False(results[0].CoversEntireDocument);
        Assert.True(results[1].CoversEntireDocument);

        Assert.True(twiceSignedDocument.TryGetForm(out var form));
        Assert.True(form.TryGetField("Signature1", out var firstFieldBase));
        Assert.True(form.TryGetField("Signature2", out var secondFieldBase));

        var firstSignature = Assert.IsType<AcroSignatureField>(firstFieldBase);
        var secondSignature = Assert.IsType<AcroSignatureField>(secondFieldBase);
        Assert.NotNull(firstSignature.SignatureValue);
        Assert.NotNull(secondSignature.SignatureValue);

        Assert.Equal(firstSignedBytes.Length, firstSignature.SignatureValue.ByteRange[2] + firstSignature.SignatureValue.ByteRange[3]);
        Assert.Equal(secondSignedBytes.Length, secondSignature.SignatureValue.ByteRange[2] + secondSignature.SignatureValue.ByteRange[3]);

        Assert.Equal("First name", firstSignature.SignatureValue.Metadata.Name);
        Assert.Null(firstSignature.SignatureValue.Metadata.ContactInfo);
        Assert.Equal("Second signature", secondSignature.SignatureValue.Metadata.Reason);
        Assert.Equal("Second contact info", secondSignature.SignatureValue.Metadata.ContactInfo);
        Assert.Null(secondSignature.SignatureValue.Metadata.Name);
    }

    [Fact]
    public async Task SignAsyncValidationReportsMissingByteRangeWhenByteRangeKeyIsRemoved()
    {
        using var certificate = CreateSelfSignedRsaCertificate();
        var signedBytes = await CreateSignedPdfAsync(certificate, "Signature1");
        var tamperedBytes = ReplaceAscii(signedBytes, "/ByteRange", "/ByteRonge");

        using var document = PdfDocument.Open(new MemoryStream(tamperedBytes, writable: false));
        var result = Assert.Single(document.GetSignatures(CreateVerificationOptions(certificate))!);

        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.ByteRangeMissing, result.ValidationError);
    }

    [Fact]
    public async Task SignAsyncValidationReportsInvalidByteRangeWhenByteRangeValuesAreCorrupted()
    {
        using var certificate = CreateSelfSignedRsaCertificate();
        var signedBytes = await CreateSignedPdfAsync(certificate, "Signature1");
        var tamperedBytes = ReplaceByteRangeArray(signedBytes, "[00000000000000000000 00000000000000000001 00000000000000000002 99999999999999999999]");

        using var document = PdfDocument.Open(new MemoryStream(tamperedBytes, writable: false));
        var result = Assert.Single(document.GetSignatures(CreateVerificationOptions(certificate))!);

        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.ByteRangeInvalid, result.ValidationError);
    }

    [Fact]
    public async Task SignAsyncValidationReportsPartialCoverageWhenLength1DoesNotMatchContentsFieldValueLength()
    {
        using var certificate = CreateSelfSignedRsaCertificate();
        var signedBytes = await CreateSignedPdfAsync(certificate, "Signature1");

        using var signedDocument = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        Assert.True(signedDocument.TryGetForm(out var form));
        var signatureField = Assert.Single(form.GetFields().OfType<AcroSignatureField>());
        Assert.NotNull(signatureField.SignatureValue);

        var byteRange = signatureField.SignatureValue.ByteRange;
        var tamperedByteRange = string.Format(
            System.Globalization.CultureInfo.InvariantCulture,
            "[{0:D20} {1:D20} {2:D20} {3:D20}]",
            byteRange[0],
            byteRange[1] + 1,
            byteRange[2],
            byteRange[3]);

        var tamperedBytes = ReplaceByteRangeArray(signedBytes, tamperedByteRange);

        using var tamperedDocument = PdfDocument.Open(new MemoryStream(tamperedBytes, writable: false));
        var result = Assert.Single(tamperedDocument.GetSignatures(CreateVerificationOptions(certificate))!);

        Assert.False(result.CoversEntireDocument);
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task SignAsyncValidationRejectsByteRangeExcludingASpanOtherThanTheContents()
    {
        using var certificate = CreateSelfSignedRsaCertificate();
        var signedBytes = await CreateSignedPdfAsync(certificate, "Signature1");

        long[] byteRange;

        using (var signedDocument = PdfDocument.Open(new MemoryStream(signedBytes, writable: false)))
        {
            Assert.True(signedDocument.TryGetForm(out var form));
            var signatureField = Assert.Single(form.GetFields().OfType<AcroSignatureField>());
            Assert.NotNull(signatureField.SignatureValue);
            byteRange = signatureField.SignatureValue.ByteRange.ToArray();
        }

        // Slide the excluded gap earlier in the file, keeping its size, the declared spans and the
        // total document length identical. The gap now hides real document bytes rather than the
        // /Contents value, but the file is still self-consistent by every length-based measure:
        // the gap size still equals the serialized length of the /Contents token, and the second
        // span still runs to the end of the file. Only a positional check rejects this.
        const int shift = 64;
        var gapLength = byteRange[2] - byteRange[1];

        var shiftedByteRange = string.Format(
            System.Globalization.CultureInfo.InvariantCulture,
            "[{0:D20} {1:D20} {2:D20} {3:D20}]",
            byteRange[0],
            byteRange[1] - shift,
            byteRange[2] - shift,
            byteRange[3] + shift);

        var tamperedBytes = ReplaceByteRangeArray(signedBytes, shiftedByteRange);

        using var tamperedDocument = PdfDocument.Open(new MemoryStream(tamperedBytes, writable: false));
        Assert.True(tamperedDocument.TryGetForm(out var tamperedForm));
        var tamperedField = Assert.Single(tamperedForm.GetFields().OfType<AcroSignatureField>());
        var tamperedRange = tamperedField.SignatureValue!.ByteRange;

        // The gap is still exactly as wide as the /Contents token and the spans still reach EOF,
        // so the tampered file satisfies the length-only invariant this check replaced.
        Assert.Equal(gapLength, tamperedRange[2] - tamperedRange[1]);
        Assert.Equal(tamperedBytes.Length, tamperedRange[2] + tamperedRange[3]);

        var result = Assert.Single(tamperedDocument.GetSignatures(CreateVerificationOptions(certificate))!);

        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.ByteRangeInvalid, result.ValidationError);
        Assert.False(result.CoversEntireDocument);
    }

    [Fact]
    public async Task SignAsyncValidationReportsContentAppendedAfterTheOutermostSignature()
    {
        using var certificate = CreateSelfSignedRsaCertificate();
        var signedBytes = await CreateSignedPdfAsync(certificate, "Signature1");

        // Append bytes the signature cannot cover. Everything it did sign is untouched, so the CMS
        // payload still verifies against the byte ranges and only the coverage check can catch this.
        var appended = System.Text.Encoding.ASCII.GetBytes("\n% content added after signing\n");
        var tamperedBytes = signedBytes.Concat(appended).ToArray();

        using var tamperedDocument = PdfDocument.Open(new MemoryStream(tamperedBytes, writable: false));
        var result = Assert.Single(tamperedDocument.GetSignatures(CreateVerificationOptions(certificate))!);

        Assert.False(result.CoversEntireDocument);
        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.DocumentModifiedAfterSigning, result.ValidationError);
        Assert.Throws<InvalidOperationException>(() => result.ThrowIfInvalid());

        // The signer is still reported, so callers can tell "signed then modified" from "not signed".
        Assert.NotNull(result.Certificate);
    }

    [Fact]
    public async Task SignAsyncValidationAcceptsEarlierSignatureSupersededByALaterOne()
    {
        using var certificate = CreateSelfSignedRsaCertificate();

        var firstSignedBytes = await CreateSignedPdfAsync(certificate, "Signature1");

        byte[] secondSignedBytes;

        using (var secondSource = PdfDocument.Open(new MemoryStream(firstSignedBytes, writable: false)))
        using (var secondOutput = new MemoryStream())
        {
            await PdfSigner.SignAsync(
                secondSource,
                secondOutput,
                new CmsDetachedSignatureProvider(certificate),
                new PdfSignatureOptions { FieldName = "Signature2" });

            secondSignedBytes = secondOutput.ToArray();
        }

        using var twiceSigned = PdfDocument.Open(new MemoryStream(secondSignedBytes, writable: false));
        var results = twiceSigned.GetSignatures(CreateVerificationOptions(certificate))!;

        // The first signature does not reach the end of the file, but the second one does, so the
        // appended revision is accounted for and neither signature is reported as modified.
        Assert.Equal(2, results.Count);
        Assert.All(results, x => x.ThrowIfInvalid());
        Assert.False(results[0].CoversEntireDocument);
        Assert.True(results[1].CoversEntireDocument);
    }

    [Fact]
    public async Task SignAsyncThrowsForEncryptedDocuments()
    {
        using var certificate = CreateSelfSignedRsaCertificate();
        using var document = PdfDocument.Open(
            IntegrationHelpers.GetSpecificTestDocumentPath("encrypted-password-is-password.pdf"),
            new ParsingOptions { Password = "password" });

        Assert.True(document.IsEncrypted);

        using var output = new MemoryStream();

        await Assert.ThrowsAsync<NotSupportedException>(() => PdfSigner.SignAsync(
            document,
            output,
            new CmsDetachedSignatureProvider(certificate),
            new PdfSignatureOptions
            {
                FieldName = "Signature1"
            }).AsTask());

        Assert.Equal(0, output.Length);
    }

    [Theory]
    [InlineData(null, 1024, "Adobe.PPKLite", "adbe.pkcs7.detached", "SHA-256", typeof(ArgumentException))]
    [InlineData("", 1024, "Adobe.PPKLite", "adbe.pkcs7.detached", "SHA-256", typeof(ArgumentException))]
    [InlineData("Signature1", 0, "Adobe.PPKLite", "adbe.pkcs7.detached", "SHA-256", typeof(ArgumentOutOfRangeException))]
    [InlineData("Signature1", 1024, null, "adbe.pkcs7.detached", "SHA-256", typeof(ArgumentException))]
    [InlineData("Signature1", 1024, "Adobe.PPKLite", null, "SHA-256", typeof(ArgumentException))]
    [InlineData("Signature1", 1024, "Adobe.PPKLite", "adbe.pkcs7.detached", null, typeof(ArgumentException))]
    public async Task SignAsyncValidatesRequiredOptions(string? fieldName, int reservedContentsLength, string? filter, string? subFilter, string? digestAlgorithm, Type expectedExceptionType)
    {
        using var certificate = CreateSelfSignedRsaCertificate();
        using var document = PdfDocument.Open(CreateUnsignedPdf());
        using var output = new MemoryStream();

        var exception = await Assert.ThrowsAnyAsync<Exception>(() => PdfSigner.SignAsync(
            document,
            output,
            new CmsDetachedSignatureProvider(certificate),
            new PdfSignatureOptions
            {
                FieldName = fieldName!,
                ReservedContentsLength = reservedContentsLength,
                Filter = filter!,
                SubFilter = subFilter!,
                DigestAlgorithm = digestAlgorithm!
            }).AsTask());

        Assert.IsType(expectedExceptionType, exception);
    }

    [Fact]
    public async Task SignAsyncValidatesPlacementPageNumber()
    {
        using var certificate = CreateSelfSignedRsaCertificate();
        using var document = PdfDocument.Open(CreateUnsignedPdf());
        using var output = new MemoryStream();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => PdfSigner.SignAsync(
            document,
            output,
            new CmsDetachedSignatureProvider(certificate),
            new PdfSignatureOptions
            {
                FieldName = "Signature1",
                Placement = new PdfSignatureFieldPlacement(2, new PdfRectangle(10, 10, 100, 40))
            }).AsTask());
    }

    [Fact]
    public async Task SignAsyncValidatesDuplicateFieldNames()
    {
        using var certificate = CreateSelfSignedRsaCertificate();
        var signedBytes = await CreateSignedPdfAsync(certificate, "Signature1");

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        using var output = new MemoryStream();

        await Assert.ThrowsAsync<InvalidOperationException>(() => PdfSigner.SignAsync(
            document,
            output,
            new CmsDetachedSignatureProvider(certificate),
            new PdfSignatureOptions
            {
                FieldName = "Signature1"
            }).AsTask());
    }

    [Fact]
    public async Task SignAsyncFailsWhenReservedContentsLengthIsTooSmall()
    {
        using var certificate = CreateSelfSignedRsaCertificate();
        using var document = PdfDocument.Open(CreateUnsignedPdf());
        using var output = new MemoryStream();

        await Assert.ThrowsAsync<InvalidOperationException>(() => PdfSigner.SignAsync(
            document,
            output,
            new CmsDetachedSignatureProvider(certificate),
            new PdfSignatureOptions
            {
                FieldName = "Signature1",
                ReservedContentsLength = 32
            }).AsTask());
    }

    private static async Task<byte[]> CreateSignedPdfAsync(X509Certificate2 certificate, string fieldName)
    {
        using var document = PdfDocument.Open(CreateUnsignedPdf());
        using var output = new MemoryStream();

        await PdfSigner.SignAsync(
            document,
            output,
            new CmsDetachedSignatureProvider(certificate),
            new PdfSignatureOptions
            {
                FieldName = fieldName,
                Metadata = new PdfSignatureMetadata(reason: "Signing test")
            });

        return output.ToArray();
    }

    private static byte[] CreateUnsignedPdf()
    {
        using var builder = new PdfDocumentBuilder();
        var page = builder.AddPage(PageSize.A4);
        var font = builder.AddStandard14Font(Standard14Font.Helvetica);
        page.AddText("Unsigned signing test document.", 12, new PdfPoint(30, 700), font);
        return builder.Build();
    }

    private static PdfSignatureVerificationOptions CreateVerificationOptions(params X509Certificate2[] trustedRoots)
    {
        var roots = trustedRoots.Select(RemovePrivateKey).ToArray();
        return new PdfSignatureVerificationOptions
        {
            SignatureTrust = new PdfCertificateTrustOptions
            {
                UseSystemStore = false,
                AdditionalTrustedRoots = roots,
                RevocationMode = X509RevocationMode.NoCheck
            },
            TimeStampTrust = new PdfCertificateTrustOptions
            {
                UseSystemStore = false,
                AdditionalTrustedRoots = roots,
                RevocationMode = X509RevocationMode.NoCheck
            }
        };
    }

    private static X509Certificate2 CreateSelfSignedRsaCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=PdfPig RSA Signing", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        AddSigningExtensions(request);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private static X509Certificate2 CreateSelfSignedEcdsaCertificate()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=PdfPig ECDSA Signing", ecdsa, HashAlgorithmName.SHA256);
        AddSigningExtensions(request);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private static void AddSigningExtensions(CertificateRequest request)
    {
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var enhancedKeyUsage = new OidCollection
        {
            new Oid("1.3.6.1.5.5.7.3.3")
        };

        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(enhancedKeyUsage, true));
    }

    private static byte[] ReplaceAscii(byte[] source, string oldValue, string newValue)
    {
        var text = System.Text.Encoding.ASCII.GetString(source);
        var index = text.IndexOf(oldValue, StringComparison.Ordinal);
        Assert.True(index >= 0, $"Expected to find '{oldValue}' in the signed PDF bytes.");
        Assert.Equal(oldValue.Length, newValue.Length);

        text = text.Substring(0, index) + newValue + text.Substring(index + oldValue.Length);
        return System.Text.Encoding.ASCII.GetBytes(text);
    }

    private static byte[] ReplaceByteRangeArray(byte[] source, string replacement)
    {
        var text = System.Text.Encoding.ASCII.GetString(source);
        var marker = "/ByteRange ";
        var markerIndex = text.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(markerIndex >= 0, "Expected to find /ByteRange in the signed PDF bytes.");

        var start = text.IndexOf('[', markerIndex + marker.Length);
        var end = text.IndexOf(']', start + 1);
        Assert.True(start >= 0 && end > start, "Expected to find a /ByteRange array in the signed PDF bytes.");

        var existing = text.Substring(start, end - start + 1);
        Assert.Equal(existing.Length, replacement.Length);

        text = text.Substring(0, start) + replacement + text.Substring(end + 1);
        return System.Text.Encoding.ASCII.GetBytes(text);
    }

    private sealed class CmsDetachedSignatureProvider : IPdfSignatureProvider
    {
        private readonly X509Certificate2 certificate;
        private readonly bool returnNullTimestamp;

        public CmsDetachedSignatureProvider(X509Certificate2 certificate, bool returnNullTimestamp = false)
        {
            this.certificate = certificate;
            this.returnNullTimestamp = returnNullTimestamp;
        }

        public Task<ReadOnlyMemory<byte>> SignAsync(PdfSigningRequest request, CancellationToken cancellationToken = default)
        {
            var content = new ContentInfo(request.ContentToSign);
            var signedCms = new SignedCms(content, detached: true);
            var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
            {
                IncludeOption = X509IncludeOption.EndCertOnly,
                DigestAlgorithm = new Oid(GetDigestAlgorithmOid(request.DigestAlgorithm))
            };

            signedCms.ComputeSignature(signer);
            return Task.FromResult<ReadOnlyMemory<byte>>(signedCms.Encode());
        }

        public Task<ReadOnlyMemory<byte>?> TimestampAsync(PdfTimestampRequest request, CancellationToken cancellationToken = default)
        {
            if (returnNullTimestamp)
            {
                return Task.FromResult<ReadOnlyMemory<byte>?>(null);
            }

            return Task.FromResult<ReadOnlyMemory<byte>?>(request.CmsSignature);
        }

        private static string GetDigestAlgorithmOid(string digestAlgorithm) =>
            digestAlgorithm switch
            {
                "SHA-256" => "2.16.840.1.101.3.4.2.1",
                "SHA-384" => "2.16.840.1.101.3.4.2.2",
                "SHA-512" => "2.16.840.1.101.3.4.2.3",
                _ => throw new NotSupportedException($"Unsupported digest algorithm '{digestAlgorithm}'.")
            };
    }

    /// <summary>
    /// Creates a new certificate with the private key removed
    /// </summary>
    private static X509Certificate2 RemovePrivateKey(X509Certificate2 certificate)
    {
        var bytes = certificate.Export(X509ContentType.Cert);
        return PdfSignatureVerificationTests.CreateCertificate(bytes);
    }
}