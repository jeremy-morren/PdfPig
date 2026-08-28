using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using UglyToad.PdfPig.AcroForms;
using UglyToad.PdfPig.Content;
using UglyToad.PdfPig.Core;
using UglyToad.PdfPig.Fonts.Standard14Fonts;
using UglyToad.PdfPig.Signing;
using UglyToad.PdfPig.Writer;

namespace UglyToad.PdfPig.Tests.Integration.Signing;

/// <summary>
/// Verification scenarios covering tampering, certificate trust and RFC 3161 timestamps. Every
/// certificate and timestamp token used here is created in memory, so no test contacts a network
/// service or depends on the checked-in fixture certificates expiring.
/// </summary>
public class PdfSignatureScenarioTests
{
    private const string CodeSigningEku = "1.3.6.1.5.5.7.3.3";
    private const string TimeStampingEku = "1.3.6.1.5.5.7.3.8";
    private const string TstInfoContentType = "1.2.840.113549.1.9.16.1.4";
    private const string SignatureTimeStampToken = "1.2.840.113549.1.9.16.2.14";
    private const string Sha256 = "2.16.840.1.101.3.4.2.1";
    private const string SigningCertificateV2Oid = "1.2.840.113549.1.9.16.2.47";
    private const string TestPolicy = "1.3.6.1.4.1.13762.3";
    private const string SigningReason = "Scenario reason marker";

    // Tampering

    [Fact]
    public async Task VerificationDetectsModificationOfBytesInsideTheSignedRange()
    {
        using var certificate = CreateCertificate("Tamper Signer");
        var signedBytes = await SignAsync(certificate);

        // The /Reason string sits in the signature dictionary ahead of /Contents, so it is inside the
        // first signed span. Rewriting it in place keeps the file structurally valid and every offset
        // identical: the byte range still parses and still brackets /Contents, so the corruption can
        // only be caught by the CMS digest itself.
        var tamperedBytes = ReplaceAscii(signedBytes, SigningReason, "Scenario reason TAMPER");

        using var document = PdfDocument.Open(new MemoryStream(tamperedBytes, writable: false));
        var result = Assert.Single(document.GetSignatures(CreateOptions(signatureRoots: [certificate]))!);

        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.SignatureMismatch, result.ValidationError);
    }

    [Fact]
    public async Task VerificationRejectsAnUnsupportedSubFilter()
    {
        using var certificate = CreateCertificate("SubFilter Signer");
        var signedBytes = await SignAsync(certificate);

        // Rewritten to a subfilter PdfPig recognises but does not verify, padded with trailing
        // whitespace so the name still ends where it did and every byte offset is preserved.
        var tamperedBytes = ReplaceAscii(signedBytes, "adbe.pkcs7.detached", "adbe.pkcs7.sha1    ");

        using var document = PdfDocument.Open(new MemoryStream(tamperedBytes, writable: false));
        var result = Assert.Single(document.GetSignatures(CreateOptions(signatureRoots: [certificate]))!);

        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.UnsupportedSubFilter, result.ValidationError);

        // The result still reports what was found, even though it could not be verified.
        Assert.Equal(PdfSignatureSubFilter.Pkcs7Sha1, result.SubFilter);
    }

    // PAdES / CAdES

    [Fact]
    public async Task CAdESSignatureCarryingTheSigningCertificateAttributeVerifies()
    {
        using var certificate = CreateCertificate("CAdES Signer");

        var signedBytes = await SignAsync(
            certificate,
            new CAdESSignatureProvider(certificate),
            subFilter: "ETSI.CAdES.detached");

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var result = Assert.Single(document.GetSignatures(CreateOptions(signatureRoots: [certificate]))!);

        result.ThrowIfInvalid();
        Assert.Equal(PdfSignatureSubFilter.CAdESDetached, result.SubFilter);
        Assert.True(result.CoversEntireDocument);
    }

    [Fact]
    public async Task CAdESSignatureWithoutTheSigningCertificateAttributeIsRejected()
    {
        using var certificate = CreateCertificate("Bare CAdES Signer");

        // Cryptographically sound, but the profile requires the signed attributes to commit to the
        // signing certificate and this one does not.
        var signedBytes = await SignAsync(
            certificate,
            new DetachedSignatureProvider(certificate),
            subFilter: "ETSI.CAdES.detached");

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var result = Assert.Single(document.GetSignatures(CreateOptions(signatureRoots: [certificate]))!);

        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.CmsInvalid, result.ValidationError);
        Assert.Equal(PdfSignatureSubFilter.CAdESDetached, result.SubFilter);
    }

    [Fact]
    public async Task SignatureWhoseSigningCertificateAttributeNamesADifferentCertificateIsRejected()
    {
        using var certificate = CreateCertificate("Substituted Signer");
        using var other = CreateCertificate("Some Other Certificate");

        // The attribute commits to a certificate other than the one that signed, which is exactly the
        // substitution the attribute exists to prevent. It is honoured whatever the subfilter.
        var signedBytes = await SignAsync(
            certificate,
            new CAdESSignatureProvider(certificate) { CertificateToCommitTo = other });

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var result = Assert.Single(document.GetSignatures(CreateOptions(signatureRoots: [certificate]))!);

        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.CmsInvalid, result.ValidationError);
    }

    [Fact]
    public async Task CertificateValidatorRejectionIsReportedWithItsException()
    {
        using var certificate = CreateCertificate("Rejected By Validator");
        var signedBytes = await SignAsync(certificate);

        var options = CreateOptions(signatureRoots: [certificate]);
        options.SignatureCertificateValidator = new AlwaysRejectingValidator();

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var result = Assert.Single(document.GetSignatures(options)!);

        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.CertificateValidationFailed, result.ValidationError);
        Assert.NotNull(result.CertificateValidationException);
        Assert.Contains("rejects everything", result.CertificateValidationException!.Message);

        // The validator is told which kind of signature the certificate came from.
        Assert.Equal(PdfSignatureSubFilter.Pkcs7Detached, ((AlwaysRejectingValidator)options.SignatureCertificateValidator).LastSubFilter);
    }

    [Fact]
    public async Task NoCertificateValidatorMeansNoUsageRulesAreApplied()
    {
        // A certificate with no extended key usage is rejected by the default validator; clearing the
        // validator leaves only chain building, which this certificate passes.
        using var certificate = CreateCertificate("No EKU Signer", enhancedKeyUsageOid: null);
        var signedBytes = await SignAsync(certificate);

        var options = CreateOptions(signatureRoots: [certificate]);
        options.SignatureCertificateValidator = null;

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        Assert.Single(document.GetSignatures(options)!).ThrowIfInvalid();
    }

    [Fact]
    public async Task VerificationReportsMissingContents()
    {
        using var certificate = CreateCertificate("Contents Signer");
        var signedBytes = await SignAsync(certificate);

        // Anchored on the trailing '<' so this renames the signature's /Contents rather than the
        // page's /Contents entry, which appears earlier in the file.
        var tamperedBytes = ReplaceAsciiBefore(signedBytes, "/Contents <", "/Contents", "/Contints");

        using var document = PdfDocument.Open(new MemoryStream(tamperedBytes, writable: false));
        var result = Assert.Single(document.GetSignatures(CreateOptions(signatureRoots: [certificate]))!);

        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.ContentsMissing, result.ValidationError);
    }

    [Fact]
    public async Task VerificationRejectsCmsCarryingItsOwnAttachedContent()
    {
        using var certificate = CreateCertificate("Attached Content Signer");

        // A detached signature is meant to commit to the PDF byte ranges. This provider instead signs
        // its own embedded payload, which must not be accepted in place of a signature over the file.
        var signedBytes = await SignAsync(certificate, new AttachedContentSignatureProvider(certificate));

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var result = Assert.Single(document.GetSignatures(CreateOptions(signatureRoots: [certificate]))!);

        Assert.False(result.IsValid);
    }

    // Certificate trust

    [Fact]
    public async Task VerificationRejectsASignerChainingToADifferentRoot()
    {
        using var signerRoot = CreateCertificate("Scenario Signer Root", certificateAuthority: true);
        using var otherRoot = CreateCertificate("Unrelated Root", certificateAuthority: true);
        using var signer = CreateCertificate("Leaf Under Signer Root", issuer: signerRoot);

        var signedBytes = await SignAsync(signer);

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));

        // Trust is configured, but anchored on a root this certificate does not chain to. This differs
        // from supplying no roots at all, which short-circuits before a chain is ever built.
        var result = Assert.Single(document.GetSignatures(CreateOptions(signatureRoots: [otherRoot]))!);

        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.SigningCertificateNotTrusted, result.ValidationError);
    }

    [Fact]
    public async Task VerificationReportsAnExpiredSigningCertificate()
    {
        using var certificate = CreateCertificate(
            "Expired Signer",
            notBefore: DateTimeOffset.UtcNow.AddDays(-30),
            notAfter: DateTimeOffset.UtcNow.AddSeconds(-1));

        var signedBytes = await SignAsync(certificate);

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var result = Assert.Single(document.GetSignatures(CreateOptions(signatureRoots: [certificate]))!);

        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.SigningCertificateExpired, result.ValidationError);
    }

    [Fact]
    public async Task VerificationIgnoresABackdatedSigningTimeClaim()
    {
        // The certificate has already expired, but the signer claims to have signed while it was still
        // valid. The claim lives in a CMS signed attribute, which is protected by the signer's own key
        // and so proves nothing about when the signing really happened. Honouring it would let anyone
        // holding an expired or revoked certificate produce signatures that verify as trusted.
        using var certificate = CreateCertificate(
            "Backdating Signer",
            notBefore: DateTimeOffset.UtcNow.AddDays(-30),
            notAfter: DateTimeOffset.UtcNow.AddSeconds(-1));

        var signedBytes = await SignAsync(
            certificate,
            new ClaimedSigningTimeProvider(certificate, DateTimeOffset.UtcNow.AddDays(-15)));

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var result = Assert.Single(document.GetSignatures(CreateOptions(signatureRoots: [certificate]))!);

        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.SigningCertificateExpired, result.ValidationError);

        // The claim is still surfaced for diagnostics, it just does not decide trust.
        Assert.NotNull(result.SigningTime);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("1.3.6.1.5.5.7.3.1")]
    public async Task VerificationRejectsASignerWithoutADocumentSigningEku(string? enhancedKeyUsageOid)
    {
        // A cryptographically sound signature from a certificate that was never issued for document
        // signing: no extended key usage at all, or one intended for something else entirely.
        using var certificate = CreateCertificate("Wrong EKU Signer", enhancedKeyUsageOid: enhancedKeyUsageOid);

        var signedBytes = await SignAsync(certificate);

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var result = Assert.Single(document.GetSignatures(CreateOptions(signatureRoots: [certificate]))!);

        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.CertificateValidationFailed, result.ValidationError);
    }

    [Fact]
    public async Task VerificationBuildsAChainThroughACallerSuppliedIntermediate()
    {
        using var root = CreateCertificate("Scenario Chain Root", certificateAuthority: true);
        using var intermediate = CreateCertificate("Scenario Chain Intermediate", issuer: root, certificateAuthority: true);
        using var leaf = CreateCertificate("Scenario Chain Leaf", issuer: intermediate);

        // Only the leaf travels inside the CMS, so the intermediate has to come from the options.
        var signedBytes = await SignAsync(leaf);

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var result = Assert.Single(document.GetSignatures(
            CreateOptions(signatureRoots: [root], intermediates: [intermediate]))!);

        result.ThrowIfInvalid();
    }

    // Digest algorithms

    [Theory]
    [InlineData("SHA-384")]
    [InlineData("SHA-512")]
    public async Task SigningRoundTripsWithNonDefaultDigestAlgorithms(string digestAlgorithm)
    {
        using var certificate = CreateCertificate($"Digest Signer {digestAlgorithm}");
        var signedBytes = await SignAsync(certificate, digestAlgorithm: digestAlgorithm);

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var result = Assert.Single(document.GetSignatures(CreateOptions(signatureRoots: [certificate]))!);

        result.ThrowIfInvalid();
        Assert.True(result.CoversEntireDocument);
    }

    // RFC 3161 timestamps, issued in memory.
    //
    // Issuing a token needs Rfc3161TimestampRequest and SignerInfo.AddUnsignedAttribute. On .NET
    // Framework the compiler binds to the framework's own System.Security.Cryptography.Pkcs assembly,
    // which predates both, so these tests only build on modern targets. The verification code they
    // exercise is not conditional and runs identically on every target framework.
#if NET

    [Fact]
    public async Task VerificationAcceptsAnEmbeddedTimestampToken()
    {
        using var certificate = CreateCertificate("Timestamped Signer");
        using var tsa = CreateCertificate("Scenario TSA", enhancedKeyUsageOid: TimeStampingEku);

        var signingTime = DateTimeOffset.UtcNow.AddMinutes(-5);
        var signedBytes = await SignAsync(
            certificate,
            new TimestampingSignatureProvider(certificate, tsa, signingTime, signingTime.AddMinutes(1)),
            addTimestamp: true);

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var options = CreateOptions(signatureRoots: [certificate], timestampRoots: [tsa]);

        var signature = Assert.Single(document.GetSignatures(options)!);
        signature.ThrowIfInvalid();

        var timestamp = Assert.Single(document.GetTimestampSignatures(options)!);
        timestamp.ThrowIfInvalid();
        Assert.NotNull(timestamp.TimeStampTime);
        Assert.Equal(signature.FieldName, timestamp.FieldName);
    }

    [Fact]
    public async Task VerificationValidatesTheSignerChainAtATrustedTimestampTime()
    {
        // The counterpart to VerificationIgnoresABackdatedSigningTimeClaim. The signing certificate has
        // expired, but a timestamp authority that is still trusted today vouches for the signature
        // having existed while the certificate was valid. That is an assertion the signer cannot forge,
        // so it is allowed to move the moment at which the chain is validated.
        using var certificate = CreateCertificate(
            "Timestamp Rescued Signer",
            notBefore: DateTimeOffset.UtcNow.AddDays(-30),
            notAfter: DateTimeOffset.UtcNow.AddSeconds(-1));

        // The authority's certificate must itself have been valid when it issued the token.
        using var tsa = CreateCertificate(
            "Scenario TSA",
            enhancedKeyUsageOid: TimeStampingEku,
            notBefore: DateTimeOffset.UtcNow.AddDays(-30));

        var signedBytes = await SignAsync(
            certificate,
            new TimestampingSignatureProvider(
                certificate,
                tsa,
                DateTimeOffset.UtcNow.AddDays(-16),
                DateTimeOffset.UtcNow.AddDays(-15)),
            addTimestamp: true);

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var options = CreateOptions(signatureRoots: [certificate], timestampRoots: [tsa]);

        Assert.Single(document.GetSignatures(options)!).ThrowIfInvalid();
        Assert.Single(document.GetTimestampSignatures(options)!).ThrowIfInvalid();
    }

    [Fact]
    public async Task VerificationIgnoresATimestampFromAnUntrustedAuthorityWhenDatingTheSignerChain()
    {
        // Same setup, except the authority is not trusted. Its asserted time must not be used, so the
        // expired signing certificate is judged as of now and reported as expired.
        using var certificate = CreateCertificate(
            "Untrusted Rescue Signer",
            notBefore: DateTimeOffset.UtcNow.AddDays(-30),
            notAfter: DateTimeOffset.UtcNow.AddSeconds(-1));

        // Time-valid at the moment it issues the token, so the only thing wrong with it is that the
        // caller does not trust its root.
        using var tsa = CreateCertificate(
            "Untrusted Scenario TSA",
            enhancedKeyUsageOid: TimeStampingEku,
            notBefore: DateTimeOffset.UtcNow.AddDays(-30));

        var signedBytes = await SignAsync(
            certificate,
            new TimestampingSignatureProvider(
                certificate,
                tsa,
                DateTimeOffset.UtcNow.AddDays(-16),
                DateTimeOffset.UtcNow.AddDays(-15)),
            addTimestamp: true);

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));

        // Only the signer's root is trusted, so the timestamp carries no weight.
        var result = Assert.Single(document.GetSignatures(CreateOptions(signatureRoots: [certificate]))!);

        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.SigningCertificateExpired, result.ValidationError);
    }

    [Fact]
    public async Task VerificationDetectsATimestampIssuedOverADifferentSignature()
    {
        using var certificate = CreateCertificate("Mismatched Timestamp Signer");
        using var tsa = CreateCertificate("Scenario TSA", enhancedKeyUsageOid: TimeStampingEku);

        var signingTime = DateTimeOffset.UtcNow.AddMinutes(-5);
        var provider = new TimestampingSignatureProvider(certificate, tsa, signingTime, signingTime.AddMinutes(1))
        {
            // A well-formed token whose message imprint commits to something other than this signature.
            MessageHashOverride = Sha256Of("a different signature value")
        };

        var signedBytes = await SignAsync(certificate, provider, addTimestamp: true);

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var options = CreateOptions(signatureRoots: [certificate], timestampRoots: [tsa]);

        var timestamp = Assert.Single(document.GetTimestampSignatures(options)!);

        Assert.False(timestamp.IsValid);
        Assert.Equal(PdfSignatureError.TimeStampTokenMismatch, timestamp.ValidationError);
    }

    [Fact]
    public async Task VerificationDetectsATimestampPredatingTheSigningTime()
    {
        using var certificate = CreateCertificate("Backdated Timestamp Signer");
        using var tsa = CreateCertificate("Scenario TSA", enhancedKeyUsageOid: TimeStampingEku);

        var signingTime = DateTimeOffset.UtcNow.AddMinutes(-5);
        var signedBytes = await SignAsync(
            certificate,
            new TimestampingSignatureProvider(certificate, tsa, signingTime, signingTime.AddMinutes(-10)),
            addTimestamp: true);

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var options = CreateOptions(signatureRoots: [certificate], timestampRoots: [tsa]);

        var timestamp = Assert.Single(document.GetTimestampSignatures(options)!);

        Assert.False(timestamp.IsValid);
        Assert.Equal(PdfSignatureError.TimeStampBeforeSigning, timestamp.ValidationError);
    }

    [Fact]
    public async Task VerificationRejectsATimestampFromAnUntrustedAuthority()
    {
        using var certificate = CreateCertificate("Untrusted TSA Signer");
        using var tsa = CreateCertificate("Untrusted TSA", enhancedKeyUsageOid: TimeStampingEku);
        using var otherTsaRoot = CreateCertificate("Unrelated TSA Root", certificateAuthority: true);

        var signingTime = DateTimeOffset.UtcNow.AddMinutes(-5);
        var signedBytes = await SignAsync(
            certificate,
            new TimestampingSignatureProvider(certificate, tsa, signingTime, signingTime.AddMinutes(1)),
            addTimestamp: true);

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));

        // Signer trust and timestamp trust are configured independently, so the signature stays valid
        // while the timestamp is rejected.
        var options = CreateOptions(signatureRoots: [certificate], timestampRoots: [otherTsaRoot]);

        Assert.Single(document.GetSignatures(options)!).ThrowIfInvalid();

        var timestamp = Assert.Single(document.GetTimestampSignatures(options)!);
        Assert.False(timestamp.IsValid);
        Assert.Equal(PdfSignatureError.TimeStampCertificateNotTrusted, timestamp.ValidationError);
    }

    [Fact]
    public async Task VerificationRejectsATimestampWhoseAuthorityLacksTheTimeStampingEku()
    {
        using var certificate = CreateCertificate("Wrong EKU TSA Signer");
        using var tsa = CreateCertificate("Wrong EKU TSA", enhancedKeyUsageOid: CodeSigningEku);

        var signingTime = DateTimeOffset.UtcNow.AddMinutes(-5);
        var signedBytes = await SignAsync(
            certificate,
            new TimestampingSignatureProvider(certificate, tsa, signingTime, signingTime.AddMinutes(1)),
            addTimestamp: true);

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var options = CreateOptions(signatureRoots: [certificate], timestampRoots: [tsa]);

        var timestamp = Assert.Single(document.GetTimestampSignatures(options)!);

        Assert.False(timestamp.IsValid);
        Assert.Equal(PdfSignatureError.CertificateValidationFailed, timestamp.ValidationError);
        Assert.NotNull(timestamp.CertificateValidationException);
    }

    [Fact]
    public async Task VerificationRejectsAMalformedTimestampToken()
    {
        using var certificate = CreateCertificate("Malformed Timestamp Signer");
        using var tsa = CreateCertificate("Scenario TSA", enhancedKeyUsageOid: TimeStampingEku);

        var signingTime = DateTimeOffset.UtcNow.AddMinutes(-5);
        var provider = new TimestampingSignatureProvider(certificate, tsa, signingTime, signingTime.AddMinutes(1))
        {
            EmitMalformedToken = true
        };

        var signedBytes = await SignAsync(certificate, provider, addTimestamp: true);

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var options = CreateOptions(signatureRoots: [certificate], timestampRoots: [tsa]);

        var timestamp = Assert.Single(document.GetTimestampSignatures(options)!);

        Assert.False(timestamp.IsValid);
        Assert.Equal(PdfSignatureError.TimeStampTokenInvalid, timestamp.ValidationError);
    }

#endif

    // The operating system trust store, against a real-world signature

    [SkippableFact]
    public void SystemTrustStoreValidatesAPubliclyTrustedRealWorldSignature()
    {
        // Public Law 118-1 as published by the U.S. Government Publishing Office. GPO signs its
        // authenticated PDFs with a certificate issued by the DigiCert Document Signing CA, whose root
        // ships in every mainstream operating system trust store, so this is the one case that can
        // exercise UseSystemStore end to end. The document is a work of the U.S. Government and is in
        // the public domain under 17 U.S.C. 105.
        using var document = PdfDocument.Open(
            IntegrationHelpers.GetSpecificTestDocumentPath("govinfo-plaw-118publ1-signed.pdf"));

        var result = Assert.Single(document.GetSignatures(new PdfSignatureVerificationOptions
        {
            SignatureTrust = new PdfCertificateTrustOptions
            {
                UseSystemStore = true,

                // The point of this test is chain building against the OS root store. Revocation is
                // left unchecked so it does not also depend on reaching an OCSP responder.
                RevocationMode = X509RevocationMode.NoCheck
            }
        })!);

        // GPO re-signs periodically and this certificate expires in March 2027. Signatures are dated as
        // of now unless a trusted timestamp says otherwise, and this one carries none, so the fixture
        // will age out. Skip rather than fail when it does: refresh it from govinfo.gov to restore
        // coverage. Likewise skip where the host has no usable root store.
        Skip.If(
            result.ValidationError is PdfSignatureError.SigningCertificateExpired
                or PdfSignatureError.SigningCertificateNotTrusted,
            $"Skipped because the checked-in GPO fixture is no longer verifiable in this environment ({result.ValidationError}). " +
            "Download a current authenticated PDF from govinfo.gov to refresh it.");

        result.ThrowIfInvalid();
        Assert.True(result.CoversEntireDocument);
        Assert.Equal("USGPOSignature", result.FieldName);
        Assert.Contains("DigiCert", result.Certificate!.Issuer);
    }

    [Fact]
    public async Task SystemTrustStoreRejectsASignerItDoesNotKnow()
    {
        // The deterministic half of the system-store coverage: a self-signed certificate that is not in
        // any root store must not be trusted. Unlike the fixture above this needs no network, no OS
        // trust content and never ages out.
        using var certificate = CreateCertificate("Not In Any Root Store");
        var signedBytes = await SignAsync(certificate);

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));

        var result = Assert.Single(document.GetSignatures(new PdfSignatureVerificationOptions
        {
            SignatureTrust = new PdfCertificateTrustOptions
            {
                UseSystemStore = true,
                RevocationMode = X509RevocationMode.NoCheck
            }
        })!);

        Assert.False(result.IsValid);
        Assert.Equal(PdfSignatureError.SigningCertificateNotTrusted, result.ValidationError);
    }

    // Behaviour of the read API itself

    [Fact]
    public async Task GetSignaturesReturnsTheSameVerdictWhenCalledRepeatedly()
    {
        using var certificate = CreateCertificate("Repeat Signer");
        var signedBytes = await SignAsync(certificate);

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var options = CreateOptions(signatureRoots: [certificate]);

        var first = Assert.Single(document.GetSignatures(options)!);
        var second = Assert.Single(document.GetSignatures(options)!);

        // Verification seeks around the input bytes, so a stale stream position would surface here.
        Assert.Equal(first.IsValid, second.IsValid);
        Assert.Equal(first.ValidationError, second.ValidationError);
        Assert.Equal(first.CoversEntireDocument, second.CoversEntireDocument);
        Assert.Equal(first.FieldName, second.FieldName);
    }

    [Fact]
    public async Task PageTextRemainsReadableAfterSigning()
    {
        using var certificate = CreateCertificate("Readable Signer");
        var signedBytes = await SignAsync(certificate);

        using var document = PdfDocument.Open(new MemoryStream(signedBytes, writable: false));
        var page = document.GetPage(1);

        Assert.Contains("Scenario", page.Text);
    }

    // Helpers

    private static async Task<byte[]> SignAsync(
        X509Certificate2 certificate,
        IPdfSignatureProvider? provider = null,
        string digestAlgorithm = "SHA-256",
        bool addTimestamp = false,
        string subFilter = "adbe.pkcs7.detached")
    {
        using var document = PdfDocument.Open(CreateUnsignedPdf());
        using var output = new MemoryStream();

        await PdfSigner.SignAsync(
            document,
            output,
            provider ?? new DetachedSignatureProvider(certificate),
            new PdfSignatureOptions
            {
                FieldName = "Signature1",
                DigestAlgorithm = digestAlgorithm,
                SubFilter = subFilter,
                AddTimestamp = addTimestamp,
                Metadata = new PdfSignatureMetadata(reason: SigningReason)
            });

        return output.ToArray();
    }

    /// <summary>
    /// Builds an ESS <c>SigningCertificateV2</c> attribute value committing to a certificate. The hash
    /// algorithm is omitted, which per the ASN.1 default means SHA-256.
    /// </summary>
    private static byte[] CreateSigningCertificateV2(X509Certificate2 certificate)
    {
        using var sha256 = SHA256.Create();
        var certificateHash = sha256.ComputeHash(certificate.RawData);

        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence())      // SigningCertificateV2
        using (writer.PushSequence())      // certs
        using (writer.PushSequence())      // ESSCertIDv2
        {
            writer.WriteOctetString(certificateHash);
        }

        return writer.Encode();
    }

    private static byte[] CreateUnsignedPdf()
    {
        using var builder = new PdfDocumentBuilder();
        var page = builder.AddPage(PageSize.A4);
        var font = builder.AddStandard14Font(Standard14Font.Helvetica);
        page.AddText("Scenario signing test document.", 12, new PdfPoint(30, 700), font);
        return builder.Build();
    }

    /// <summary>
    /// Builds verification options with signature trust and timestamp trust configured separately, as
    /// the API intends. <paramref name="timestampRoots"/> defaults to <paramref name="signatureRoots"/>
    /// only for the tests where the distinction is not what is under test.
    /// </summary>
    private static PdfSignatureVerificationOptions CreateOptions(
        IReadOnlyList<X509Certificate2>? signatureRoots = null,
        IReadOnlyList<X509Certificate2>? timestampRoots = null,
        IReadOnlyList<X509Certificate2>? intermediates = null)
    {
        return new PdfSignatureVerificationOptions
        {
            SignatureTrust = CreateTrust(signatureRoots, intermediates),
            TimeStampTrust = CreateTrust(timestampRoots ?? signatureRoots, intermediates)
        };
    }

    private static PdfCertificateTrustOptions CreateTrust(
        IReadOnlyList<X509Certificate2>? roots,
        IReadOnlyList<X509Certificate2>? intermediates)
    {
        return new PdfCertificateTrustOptions
        {
            UseSystemStore = false,
            AdditionalTrustedRoots = (roots ?? []).Select(PublicCopy).ToArray(),
            AdditionalIntermediateCertificates = (intermediates ?? []).Select(PublicCopy).ToArray(),

            // Revocation is deliberately not checked: these certificates carry no CRL distribution
            // point or OCSP responder, and reaching one would mean depending on a network service.
            RevocationMode = X509RevocationMode.NoCheck
        };
    }

    private static X509Certificate2 PublicCopy(X509Certificate2 certificate) =>
        PdfSignatureVerificationTests.CreateCertificate(certificate.Export(X509ContentType.Cert));

    private static X509Certificate2 CreateCertificate(
        string subject,
        X509Certificate2? issuer = null,
        bool certificateAuthority = false,
        string? enhancedKeyUsageOid = CodeSigningEku,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        var key = RSA.Create(2048);

        try
        {
            var request = new CertificateRequest($"CN={subject}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                certificateAuthority
                    ? X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign
                    : X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation,
                true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

            if (enhancedKeyUsageOid != null)
            {
                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(enhancedKeyUsageOid) }, true));
            }

            var from = notBefore ?? DateTimeOffset.UtcNow.AddDays(-1);
            var to = notAfter ?? DateTimeOffset.UtcNow.AddDays(30);

            if (issuer is null)
            {
                return request.CreateSelfSigned(from, to);
            }

            // Keep the issued certificate inside the issuer's own validity window so the chain does not
            // fail for a reason the test did not intend.
            var issuerNotBefore = new DateTimeOffset(issuer.NotBefore.ToUniversalTime(), TimeSpan.Zero);
            var issuerNotAfter = new DateTimeOffset(issuer.NotAfter.ToUniversalTime(), TimeSpan.Zero);

            if (from < issuerNotBefore)
            {
                from = issuerNotBefore;
            }

            if (to > issuerNotAfter)
            {
                to = issuerNotAfter;
            }

            using var issued = request.Create(issuer, from, to, Guid.NewGuid().ToByteArray());
            return issued.CopyWithPrivateKey(key);
        }
        finally
        {
            key.Dispose();
        }
    }

    private static byte[] ReplaceAscii(byte[] source, string oldValue, string newValue)
    {
        Assert.Equal(oldValue.Length, newValue.Length);

        var text = System.Text.Encoding.ASCII.GetString(source);
        var index = text.IndexOf(oldValue, StringComparison.Ordinal);
        Assert.True(index >= 0, $"Expected to find '{oldValue}' in the signed PDF bytes.");

        var replaced = text.Substring(0, index) + newValue + text.Substring(index + oldValue.Length);
        return System.Text.Encoding.ASCII.GetBytes(replaced);
    }

    /// <summary>
    /// Replaces <paramref name="oldValue"/> at the position located by <paramref name="anchor"/>, for
    /// cases where the value to change also occurs elsewhere in the file.
    /// </summary>
    private static byte[] ReplaceAsciiBefore(byte[] source, string anchor, string oldValue, string newValue)
    {
        Assert.Equal(oldValue.Length, newValue.Length);

        var text = System.Text.Encoding.ASCII.GetString(source);
        var anchorIndex = text.IndexOf(anchor, StringComparison.Ordinal);
        Assert.True(anchorIndex >= 0, $"Expected to find '{anchor}' in the signed PDF bytes.");
        Assert.Equal(oldValue, text.Substring(anchorIndex, oldValue.Length));

        var replaced = text.Substring(0, anchorIndex) + newValue + text.Substring(anchorIndex + oldValue.Length);
        return System.Text.Encoding.ASCII.GetBytes(replaced);
    }

    private static string GetDigestOid(string digestAlgorithm) => digestAlgorithm switch
    {
        "SHA-256" => Sha256,
        "SHA-384" => "2.16.840.1.101.3.4.2.2",
        "SHA-512" => "2.16.840.1.101.3.4.2.3",
        _ => throw new NotSupportedException($"Unsupported digest algorithm '{digestAlgorithm}'.")
    };

#if NET

    private static byte[] Sha256Of(string value)
    {
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(value));
    }

    /// <summary>
    /// Builds an RFC 3161 timestamp token entirely in memory, standing in for a Time Stamp Authority.
    /// </summary>
    private static byte[] CreateTimestampToken(
        SignerInfo signerInfo,
        X509Certificate2 tsaCertificate,
        DateTimeOffset generationTime,
        byte[]? messageHashOverride)
    {
        var request = Rfc3161TimestampRequest.CreateFromSignerInfo(signerInfo, HashAlgorithmName.SHA256);
        var messageHash = messageHashOverride ?? request.GetMessageHash().ToArray();

        // TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, ... }
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            writer.WriteInteger(1);
            writer.WriteObjectIdentifier(TestPolicy);

            using (writer.PushSequence())
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(Sha256);
                    writer.WriteNull();
                }

                writer.WriteOctetString(messageHash);
            }

            writer.WriteInteger(1);
            writer.WriteGeneralizedTime(generationTime);
        }

        var timestampCms = new SignedCms(new ContentInfo(new Oid(TstInfoContentType), writer.Encode()), detached: false);

        timestampCms.ComputeSignature(new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, tsaCertificate)
        {
            IncludeOption = X509IncludeOption.EndCertOnly
        });

        return timestampCms.Encode();
    }

#endif

    private sealed class DetachedSignatureProvider : IPdfSignatureProvider
    {
        private readonly X509Certificate2 certificate;

        public DetachedSignatureProvider(X509Certificate2 certificate)
        {
            this.certificate = certificate;
        }

        public Task<ReadOnlyMemory<byte>> SignAsync(PdfSigningRequest request, CancellationToken cancellationToken = default)
        {
            var cms = new SignedCms(new ContentInfo(request.ContentToSign), detached: true);

            cms.ComputeSignature(new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
            {
                IncludeOption = X509IncludeOption.EndCertOnly,
                DigestAlgorithm = new Oid(GetDigestOid(request.DigestAlgorithm))
            });

            return Task.FromResult<ReadOnlyMemory<byte>>(cms.Encode());
        }

        public Task<ReadOnlyMemory<byte>?> TimestampAsync(PdfTimestampRequest request, CancellationToken cancellationToken = default) =>
            Task.FromResult<ReadOnlyMemory<byte>?>(null);
    }

    /// <summary>
    /// Produces a detached CMS signature carrying the ESS signing-certificate attribute that CAdES
    /// requires.
    /// </summary>
    private sealed class CAdESSignatureProvider : IPdfSignatureProvider
    {
        private readonly X509Certificate2 certificate;

        public CAdESSignatureProvider(X509Certificate2 certificate)
        {
            this.certificate = certificate;
        }

        /// <summary>
        /// The certificate the attribute commits to. Defaults to the one actually signing.
        /// </summary>
        public X509Certificate2? CertificateToCommitTo { get; init; }

        public Task<ReadOnlyMemory<byte>> SignAsync(PdfSigningRequest request, CancellationToken cancellationToken = default)
        {
            var cms = new SignedCms(new ContentInfo(request.ContentToSign), detached: true);

            var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
            {
                IncludeOption = X509IncludeOption.EndCertOnly,
                DigestAlgorithm = new Oid(GetDigestOid(request.DigestAlgorithm))
            };

            signer.SignedAttributes.Add(new AsnEncodedData(
                new Oid(SigningCertificateV2Oid),
                CreateSigningCertificateV2(CertificateToCommitTo ?? certificate)));

            cms.ComputeSignature(signer);
            return Task.FromResult<ReadOnlyMemory<byte>>(cms.Encode());
        }

        public Task<ReadOnlyMemory<byte>?> TimestampAsync(PdfTimestampRequest request, CancellationToken cancellationToken = default) =>
            Task.FromResult<ReadOnlyMemory<byte>?>(null);
    }

    /// <summary>
    /// Rejects every certificate, recording the subfilter it was told about.
    /// </summary>
    private sealed class AlwaysRejectingValidator : ICertificateValidator
    {
        public PdfSignatureSubFilter LastSubFilter { get; private set; }

        public void ValidateCertificate(X509Certificate2 certificate, PdfSignatureSubFilter subFilter)
        {
            LastSubFilter = subFilter;
            throw new PdfCertificateValidationFailedException("This validator rejects everything.");
        }
    }

    /// <summary>
    /// Signs the byte ranges correctly, but asserts a signing time of its own choosing.
    /// </summary>
    private sealed class ClaimedSigningTimeProvider : IPdfSignatureProvider
    {
        private readonly X509Certificate2 certificate;
        private readonly DateTimeOffset claimedSigningTime;

        public ClaimedSigningTimeProvider(X509Certificate2 certificate, DateTimeOffset claimedSigningTime)
        {
            this.certificate = certificate;
            this.claimedSigningTime = claimedSigningTime;
        }

        public Task<ReadOnlyMemory<byte>> SignAsync(PdfSigningRequest request, CancellationToken cancellationToken = default)
        {
            var cms = new SignedCms(new ContentInfo(request.ContentToSign), detached: true);

            var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
            {
                IncludeOption = X509IncludeOption.EndCertOnly,
                DigestAlgorithm = new Oid(GetDigestOid(request.DigestAlgorithm))
            };

            signer.SignedAttributes.Add(new Pkcs9SigningTime(claimedSigningTime.UtcDateTime));

            cms.ComputeSignature(signer);
            return Task.FromResult<ReadOnlyMemory<byte>>(cms.Encode());
        }

        public Task<ReadOnlyMemory<byte>?> TimestampAsync(PdfTimestampRequest request, CancellationToken cancellationToken = default) =>
            Task.FromResult<ReadOnlyMemory<byte>?>(null);
    }

    /// <summary>
    /// Signs a payload of its own choosing and embeds it, rather than signing the PDF byte ranges.
    /// </summary>
    private sealed class AttachedContentSignatureProvider : IPdfSignatureProvider
    {
        private readonly X509Certificate2 certificate;

        public AttachedContentSignatureProvider(X509Certificate2 certificate)
        {
            this.certificate = certificate;
        }

        public Task<ReadOnlyMemory<byte>> SignAsync(PdfSigningRequest request, CancellationToken cancellationToken = default)
        {
            var cms = new SignedCms(new ContentInfo("content the signer chose, not the document"u8.ToArray()), detached: false);

            cms.ComputeSignature(new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
            {
                IncludeOption = X509IncludeOption.EndCertOnly,
                DigestAlgorithm = new Oid(GetDigestOid(request.DigestAlgorithm))
            });

            return Task.FromResult<ReadOnlyMemory<byte>>(cms.Encode());
        }

        public Task<ReadOnlyMemory<byte>?> TimestampAsync(PdfTimestampRequest request, CancellationToken cancellationToken = default) =>
            Task.FromResult<ReadOnlyMemory<byte>?>(null);
    }

#if NET

    private sealed class TimestampingSignatureProvider : IPdfSignatureProvider
    {
        private readonly X509Certificate2 certificate;
        private readonly X509Certificate2 tsaCertificate;
        private readonly DateTimeOffset signingTime;
        private readonly DateTimeOffset generationTime;

        public TimestampingSignatureProvider(
            X509Certificate2 certificate,
            X509Certificate2 tsaCertificate,
            DateTimeOffset signingTime,
            DateTimeOffset generationTime)
        {
            this.certificate = certificate;
            this.tsaCertificate = tsaCertificate;
            this.signingTime = signingTime;
            this.generationTime = generationTime;
        }

        public byte[]? MessageHashOverride { get; init; }

        public bool EmitMalformedToken { get; init; }

        public Task<ReadOnlyMemory<byte>> SignAsync(PdfSigningRequest request, CancellationToken cancellationToken = default)
        {
            var cms = new SignedCms(new ContentInfo(request.ContentToSign), detached: true);

            var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
            {
                IncludeOption = X509IncludeOption.EndCertOnly,
                DigestAlgorithm = new Oid(GetDigestOid(request.DigestAlgorithm))
            };

            signer.SignedAttributes.Add(new Pkcs9SigningTime(signingTime.UtcDateTime));

            cms.ComputeSignature(signer);
            return Task.FromResult<ReadOnlyMemory<byte>>(cms.Encode());
        }

        public Task<ReadOnlyMemory<byte>?> TimestampAsync(PdfTimestampRequest request, CancellationToken cancellationToken = default)
        {
            var cms = new SignedCms();
            cms.Decode(request.CmsSignature.ToArray());

            var signerInfo = cms.SignerInfos[0];

            byte[] token;

            if (EmitMalformedToken)
            {
                // Valid DER so the attribute encodes, but not a SignedCms.
                var writer = new AsnWriter(AsnEncodingRules.DER);
                writer.WriteOctetString([1, 2, 3, 4]);
                token = writer.Encode();
            }
            else
            {
                token = CreateTimestampToken(signerInfo, tsaCertificate, generationTime, MessageHashOverride);
            }

            signerInfo.AddUnsignedAttribute(new AsnEncodedData(new Oid(SignatureTimeStampToken), token));

            return Task.FromResult<ReadOnlyMemory<byte>?>(cms.Encode());
        }
    }

#endif
}
