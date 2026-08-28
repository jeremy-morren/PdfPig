using System.Security.Cryptography.X509Certificates;
using UglyToad.PdfPig.AcroForms;
using UglyToad.PdfPig.AcroForms.Fields;
using UglyToad.PdfPig.Signing;

namespace UglyToad.PdfPig.Tests.Integration.Signing;

/// <summary>
/// End-to-end verification tests for embedded PDF signatures and timestamps.
/// </summary>
public class PdfSignatureVerificationTests
{
    /// <summary>
    /// Verifies that opening invalid PDF bytes throws an exception.
    /// </summary>
    [Fact]
    public void InvalidPdfThrowsException()
    {
        Assert.ThrowsAny<Exception>(() => PdfDocument.Open([1, 2, 3, 4]));
    }

    /// <summary>
    /// Verifies that unsigned PDFs return <see langword="null"/> for signature discovery.
    /// </summary>
    [Fact]
    public void ValidPdfWithoutSignatureReturnsNull()
    {
        using var document = PdfDocument.Open(IntegrationHelpers.GetDocumentPath("Single Page Simple - from inkscape"));

        Assert.Null(document.GetSignatures(CreateVerificationOptions()));
        Assert.Null(document.GetTimestampSignatures(CreateVerificationOptions()));
    }

    /// <summary>
    /// Verifies that signature and timestamp validation work when the document is opened from a <see cref="MemoryStream"/>.
    /// </summary>
    [Fact]
    public void SigningVerificationWorksWhenOpenedFromMemoryStream()
    {
        var bytes = File.ReadAllBytes(GetSigningFixturePath("pdfsInvalid", "signed-valid-and-timestamped-control.pdf"));

        using var stream = new MemoryStream(bytes, writable: false);
        using var document = PdfDocument.Open(stream);

        var signature = Assert.Single(document.GetSignatures(CreateVerificationOptions("certs/rsa-root-valid.cer"))!);
        var timestamp = Assert.Single(document.GetTimestampSignatures(CreateVerificationOptions("certs/rsa-root-valid.cer"))!);

        Assert.True(signature.IsValid);
        Assert.True(timestamp.IsValid);
    }

    /// <summary>
    /// Verifies a single valid PDF signature with manual trust.
    /// </summary>
    [Fact]
    public void SingleValidSignatureIsValid()
    {
        using var document = PdfDocument.Open(GetSigningFixturePath("pdfs", "signed", "rsa-leaf-valid.pdf"));

        var result = Assert.Single(document.GetSignatures(CreateVerificationOptions("certs/rsa-root-valid.cer"))!);
        result.ThrowIfInvalid();

        Assert.True(result.IsValid);
        Assert.Null(result.ValidationError);
        Assert.NotNull(result.Certificate);
        Assert.True(result.CoversEntireDocument);

    }

    /// <summary>
    /// Verifies that signed AcroForm signature fields expose immutable parsed signature metadata.
    /// </summary>
    [Fact]
    public void SignedAcroFormFieldExposesSignatureValueMetadata()
    {
        using var document = PdfDocument.Open(GetSigningFixturePath("pdfs", "signed", "rsa-leaf-valid.pdf"));

        Assert.True(document.TryGetForm(out var form));

        var signatureField = Assert.Single(form.GetFields().OfType<AcroSignatureField>());

        Assert.True(signatureField.IsSigned);
        Assert.NotNull(signatureField.SignatureValue);
        Assert.False(string.IsNullOrWhiteSpace(signatureField.SignatureValue.Filter));
        Assert.False(string.IsNullOrWhiteSpace(signatureField.SignatureValue.SubFilter));
        Assert.Equal(4, signatureField.SignatureValue.ByteRange.Count);
        Assert.True(signatureField.SignatureValue.Contents.Length > 0);
        Assert.NotNull(signatureField.SignatureValue.ModifiedDate);
        Assert.True(signatureField.Information.Reference.HasValue);
        Assert.True(form.TryGetField(signatureField.Information.Reference.Value, out var byReference));
        Assert.Same(signatureField, byReference);
    }

    /// <summary>
    /// Verifies multiple single-signature invalid inputs produce the expected validation errors.
    /// </summary>
    [Theory]
    [InlineData("pdfsInvalid/signed-with-no-eku.pdf", PdfSignatureError.CertificateValidationFailed, true)]
    [InlineData("pdfsInvalid/signed-with-different-eku.pdf", PdfSignatureError.CertificateValidationFailed, true)]
    [InlineData("pdfsInvalid/signature-field-with-invalid-cms.pdf", PdfSignatureError.CmsInvalid, true)]
    public void SingleInvalidSignatureFilesReturnExpectedError(string relativePath, PdfSignatureError expectedError, bool expectedCoversEntireDocument)
    {
        using var document = PdfDocument.Open(GetSigningFixturePath(relativePath.Split('/')));

        var result = Assert.Single(document.GetSignatures(CreateVerificationOptions("certs/rsa-root-valid.cer"))!);

        Assert.False(result.IsValid);
        Assert.Equal(expectedError, result.ValidationError);
        Assert.Equal(expectedCoversEntireDocument, result.CoversEntireDocument);
        Assert.Throws<InvalidOperationException>(result.ThrowIfInvalid);
    }

    /// <summary>
    /// Verifies that malformed byte-range entries keep the signature field readable and only fail during signature validation.
    /// </summary>
    [Theory]
    [InlineData("pdfsInvalid/signature-field-with-missing-byte-range.pdf", PdfSignatureError.ByteRangeMissing)]
    [InlineData("pdfsInvalid/signature-field-with-invalid-byte-range.pdf", PdfSignatureError.ByteRangeInvalid)]
    public void SignatureFieldsWithMalformedByteRangesRemainReadableUntilValidated(string relativePath, PdfSignatureError expectedError)
    {
        using var document = PdfDocument.Open(GetSigningFixturePath(relativePath.Split('/')));

        Assert.True(document.TryGetForm(out var form));

        var signatureField = Assert.Single(form.GetFields().OfType<AcroSignatureField>());
        Assert.True(signatureField.IsSigned);
        Assert.NotNull(signatureField.SignatureValue);
        Assert.True(signatureField.SignatureValue.Contents.Length > 0);

        var result = Assert.Single(document.GetSignatures(CreateVerificationOptions("certs/rsa-root-valid.cer"))!);

        Assert.False(result.IsValid);
        Assert.Equal(expectedError, result.ValidationError);
        Assert.False(result.CoversEntireDocument);
        Assert.Throws<InvalidOperationException>(result.ThrowIfInvalid);
    }

    /// <summary>
    /// Verifies that a valid signature becomes untrusted when manual trust is empty and system trust is disabled.
    /// </summary>
    [Fact]
    public void ValidSignatureWithoutTrustedRootIsNotTrusted()
    {
        using var document = PdfDocument.Open(GetSigningFixturePath("pdfs", "signed", "rsa-leaf-valid.pdf"));

        var result = Assert.Single(document.GetSignatures(new PdfSignatureVerificationOptions
        {
            SignatureTrust = new PdfCertificateTrustOptions
            {
                UseSystemStore = false
            },
            TimeStampTrust = new PdfCertificateTrustOptions
            {
                UseSystemStore = false
            }
        })!);

        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.SigningCertificateNotTrusted, result.ValidationError);
    }

    /// <summary>
    /// Verifies that a PDF containing multiple invalid signatures reports both validation failures.
    /// </summary>
    [Fact]
    public void MultipleInvalidSignaturesReturnTwoInvalidResults()
    {
        using var document = PdfDocument.Open(GetSigningFixturePath("pdfsInvalid", "multiple-invalid-signatures.pdf"));

        var results = document.GetSignatures(CreateVerificationOptions("certs/rsa-root-valid.cer"))!;

        Assert.Equal(2, results.Count);
        Assert.All(results, x =>
        {
            Assert.Equal(PdfSignatureError.CertificateValidationFailed, x.ValidationError);
            Assert.Throws<InvalidOperationException>(x.ThrowIfInvalid);
        });
    }

    /// <summary>
    /// Verifies that a PDF containing multiple valid signatures reports all of them as valid.
    /// </summary>
    [Fact]
    public void MultipleValidSignaturesReturnAllValidResults()
    {
        using var document = PdfDocument.Open(GetSigningFixturePath("pdfs", "signed", "multiple-valid-signatures.pdf"));

        var results = document.GetSignatures(CreateVerificationOptions("certs/ecdsa-root-valid-p384.cer"))!;

        Assert.Equal(2, results.Count);
        Assert.All(results, x => Assert.True(x.IsValid));
    }

    /// <summary>
    /// Verifies that mixed valid and invalid appended signatures preserve per-signature outcomes.
    /// </summary>
    [Fact]
    public void MixedValidAndInvalidSignaturesReturnMixedResults()
    {
        using var document = PdfDocument.Open(GetSigningFixturePath("pdfsInvalid", "mixed-valid-and-invalid-signatures.pdf"));

        var results = document.GetSignatures(CreateVerificationOptions("certs/rsa-root-valid.cer"))!;

        Assert.Equal(3, results.Count);
        Assert.True(results[0].IsValid);
        Assert.Equal(PdfSignatureError.CertificateValidationFailed, results[1].ValidationError);
        Assert.Equal(PdfSignatureError.CertificateValidationFailed, results[2].ValidationError);
    }

    /// <summary>
    /// Verifies that a valid embedded RFC 3161 timestamp token is discovered and validated.
    /// </summary>
    [Fact]
    public void ValidTimestampTokenIsValid()
    {
        using var document = PdfDocument.Open(GetSigningFixturePath("pdfsInvalid", "signed-valid-and-timestamped-control.pdf"));

        var result = Assert.Single(document.GetTimestampSignatures(CreateVerificationOptions("certs/rsa-root-valid.cer"))!);

        Assert.True(result.IsValid);
        Assert.NotNull(result.TimeStampTime);
    }

    /// <summary>
    /// Verifies that a mismatched embedded RFC 3161 timestamp token is detected.
    /// </summary>
    [Fact]
    public void InvalidTimestampTokenReturnsMismatchError()
    {
        using var document = PdfDocument.Open(GetSigningFixturePath("pdfsInvalid", "signed-valid-with-invalid-timestamp-cms.pdf"));

        var result = Assert.Single(document.GetTimestampSignatures(CreateVerificationOptions("certs/rsa-root-valid.cer"))!);

        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.TimeStampTokenMismatch, result.ValidationError);
    }

    /// <summary>
    /// Verifies a document that carries a signature but no timestamp: the signature stands on its own
    /// and <see cref="PdfDocument.GetTimestampSignatures"/> finds nothing to report.
    /// </summary>
    [Fact]
    public void SignedButNotTimestampedDocumentIsValidAndReportsNoTimestamp()
    {
        using var document = PdfDocument.Open(GetSigningFixturePath("pdfs", "signed", "rsa-leaf-valid.pdf"));

        var options = CreateVerificationOptions("certs/rsa-root-valid.cer");

        var signature = Assert.Single(document.GetSignatures(options)!);
        signature.ThrowIfInvalid();
        Assert.True(signature.CoversEntireDocument);
        Assert.Null(signature.TimeStampTime);

        Assert.Null(document.GetTimestampSignatures(options));
    }

    /// <summary>
    /// Verifies documents carrying both a signature and an embedded RFC 3161 timestamp, across the
    /// signing algorithms the fixtures cover. The ECDSA cases also chain through an intermediate.
    /// </summary>
    [Theory]
    [InlineData("rsa-leaf-valid.pdf", "certs/rsa-root-valid.cer")]
    [InlineData("ecdsa-leaf-valid-p256.pdf", "certs/ecdsa-root-valid-p384.cer")]
    [InlineData("ecdsa-leaf-valid-p384.pdf", "certs/ecdsa-root-valid-p384.cer")]
    [InlineData("ecdsa-leaf-valid-p521.pdf", "certs/ecdsa-root-valid-p384.cer")]
    public void SignedAndTimestampedDocumentsReportBothAsValid(string fileName, string signatureRoot)
    {
        using var document = PdfDocument.Open(GetSigningFixturePath("pdfs", "timestamped", fileName));

        // The signer and the timestamp authority are anchored separately, as the API intends: these
        // fixtures use an RSA timestamp authority regardless of the algorithm that signed the document.
        var options = new PdfSignatureVerificationOptions
        {
            SignatureTrust = new PdfCertificateTrustOptions
            {
                UseSystemStore = false,
                RevocationMode = X509RevocationMode.NoCheck,
                AdditionalTrustedRoots = [LoadFixtureCertificate(signatureRoot)]
            },
            TimeStampTrust = new PdfCertificateTrustOptions
            {
                UseSystemStore = false,
                RevocationMode = X509RevocationMode.NoCheck,
                AdditionalTrustedRoots = [LoadFixtureCertificate("certs/rsa-root-valid.cer")]
            }
        };

        var signature = Assert.Single(document.GetSignatures(options)!);
        signature.ThrowIfInvalid();
        Assert.True(signature.CoversEntireDocument);

        var timestamp = Assert.Single(document.GetTimestampSignatures(options)!);
        timestamp.ThrowIfInvalid();
        Assert.NotNull(timestamp.TimeStampTime);
        Assert.Equal(signature.FieldName, timestamp.FieldName);
    }

    /// <summary>
    /// Verifies that a timestamp is rejected when its authority is not trusted, while the signature it
    /// accompanies stays valid, confirming the two trust configurations are honoured independently.
    /// </summary>
    [Fact]
    public void TimestampFromAnUntrustedAuthorityDoesNotInvalidateTheSignature()
    {
        using var document = PdfDocument.Open(GetSigningFixturePath("pdfs", "timestamped", "ecdsa-leaf-valid-p256.pdf"));

        var options = new PdfSignatureVerificationOptions
        {
            SignatureTrust = new PdfCertificateTrustOptions
            {
                UseSystemStore = false,
                RevocationMode = X509RevocationMode.NoCheck,
                AdditionalTrustedRoots = [LoadFixtureCertificate("certs/ecdsa-root-valid-p384.cer")]
            },
            TimeStampTrust = new PdfCertificateTrustOptions
            {
                UseSystemStore = false,
                RevocationMode = X509RevocationMode.NoCheck,

                // Anchored on the signer's root, which the RSA timestamp authority does not chain to.
                AdditionalTrustedRoots = [LoadFixtureCertificate("certs/ecdsa-root-valid-p384.cer")]
            }
        };

        Assert.Single(document.GetSignatures(options)!).ThrowIfInvalid();

        var timestamp = Assert.Single(document.GetTimestampSignatures(options)!);
        Assert.False(timestamp.IsValid);
        Assert.Equal(PdfSignatureError.TimeStampCertificateNotTrusted, timestamp.ValidationError);
    }

    private static PdfSignatureVerificationOptions CreateVerificationOptions(params string[] trustedRootRelativePaths)
    {
        return new PdfSignatureVerificationOptions
        {
            SignatureTrust = new PdfCertificateTrustOptions
            {
                UseSystemStore = false,
                RevocationMode = X509RevocationMode.NoCheck,
                AdditionalTrustedRoots = trustedRootRelativePaths.Select(LoadFixtureCertificate).ToList()
            },
            TimeStampTrust = new PdfCertificateTrustOptions
            {
                UseSystemStore = false,
                RevocationMode = X509RevocationMode.NoCheck,
                AdditionalTrustedRoots = trustedRootRelativePaths.Select(LoadFixtureCertificate).ToList()
            }
        };
    }

    public static X509Certificate2 CreateCertificate(byte[] certificateBytes)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(certificateBytes);
#else
            return new X509Certificate2(certificateBytes);
#endif
    }

    private static X509Certificate2 LoadFixtureCertificate(string relativePath)
    {
        var certificateBytes = File.ReadAllBytes(GetSigningFixturePath(relativePath.Split('/')));
        return CreateCertificate(certificateBytes);
    }


    private static string GetSigningFixturePath(params string[] parts)
    {
        var root = new[] { AppDomain.CurrentDomain.BaseDirectory, "Integration/Signing/TestFiles" };
        return Path.Combine(root.Concat(parts).ToArray());
    }
}