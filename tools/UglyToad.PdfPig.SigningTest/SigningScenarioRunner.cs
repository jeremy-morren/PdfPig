using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace UglyToad.PdfPig.SigningTest;

internal static class SigningScenarioRunner
{
    public static void Run(string sourcePdf, string outputDirectory)
    {
        var certsDirectory = Path.Combine(outputDirectory, "certs");
        var invalidCertsDirectory = Path.Combine(outputDirectory, "certsInvalid");
        var pdfsDirectory = Path.Combine(outputDirectory, "pdfs");
        var signedPdfsDirectory = Path.Combine(pdfsDirectory, "signed");
        var timestampedPdfsDirectory = Path.Combine(pdfsDirectory, "timestamped");
        var invalidPdfsDirectory = Path.Combine(outputDirectory, "pdfsInvalid");

        Directory.CreateDirectory(outputDirectory);
        Directory.CreateDirectory(certsDirectory);
        Directory.CreateDirectory(invalidCertsDirectory);
        Directory.CreateDirectory(signedPdfsDirectory);
        Directory.CreateDirectory(timestampedPdfsDirectory);
        Directory.CreateDirectory(invalidPdfsDirectory);

        var certificateFactory = new CertificateMaterialFactory();
        var certificates = certificateFactory.CreateAll();

        WriteCertificates(certsDirectory, certificates.ValidAll);
        WriteCertificates(invalidCertsDirectory, certificates.InvalidAll);

        var pdfWriter = new PdfScenarioWriter(sourcePdf);
        WriteValidPdfScenarios(signedPdfsDirectory, timestampedPdfsDirectory, certificates.ValidLeafs, certificates.ValidTimestampAuthority, pdfWriter);
        WriteInvalidPdfScenarios(invalidPdfsDirectory, certificates, pdfWriter);
    }

    // Export each generated certificate in the same machine-readable formats without emitting companion documentation files.
    private static void WriteCertificates(string directory, IReadOnlyList<CertificateMaterial> certificates)
    {
        foreach (var certificate in certificates.OrderBy(x => x.BaseName, StringComparer.Ordinal))
        {
            var cerPath = Path.Combine(directory, certificate.BaseName + ".cer");
            var pemPath = Path.Combine(directory, certificate.BaseName + ".pem");
            var pfxPath = Path.Combine(directory, certificate.BaseName + ".pfx");
            var keyPemPath = Path.Combine(directory, certificate.BaseName + ".key.pem");

            File.WriteAllBytes(cerPath, certificate.Certificate.Export(X509ContentType.Cert));
            File.WriteAllText(pemPath, certificate.Certificate.ExportCertificatePem());
            File.WriteAllBytes(pfxPath, certificate.Certificate.Export(X509ContentType.Pfx, CertificateMaterialFactory.PfxPassword));
            File.WriteAllText(keyPemPath, certificate.PrivateKeyPem);

            if (certificate.Chain.Count > 1)
            {
                var chainPemPath = Path.Combine(directory, certificate.BaseName + ".chain.pem");
                var chainPem = string.Join(Environment.NewLine, certificate.Chain.Select(x => x.ExportCertificatePem()));
                File.WriteAllText(chainPemPath, chainPem);
            }
        }
    }

    // Produce one signed-only PDF and one signed-plus-timestamped PDF for every valid leaf certificate.
    private static void WriteValidPdfScenarios(
        string signedPdfsDirectory,
        string timestampedPdfsDirectory,
        IReadOnlyList<CertificateMaterial> validLeafs,
        CertificateMaterial tsaCertificate,
        PdfScenarioWriter pdfWriter)
    {
        foreach (var leaf in validLeafs.OrderBy(x => x.BaseName, StringComparer.Ordinal))
        {
            // Valid detached CMS signature created by the leaf certificate without an RFC 3161 timestamp.
            var signedPath = Path.Combine(signedPdfsDirectory, leaf.BaseName + ".pdf");
            var signedDescription = $"Single detached CMS signature created with {leaf.BaseName}. No RFC 3161 timestamp token is included.";
            pdfWriter.CreateSignedPdf(signedPath, leaf, signedDescription);

            // Valid detached CMS signature created by the leaf certificate and timestamped by the dedicated TSA certificate.
            var timestampedPath = Path.Combine(timestampedPdfsDirectory, leaf.BaseName + ".pdf");
            var timestampedDescription = $"Single detached CMS signature created with {leaf.BaseName} and an RFC 3161 timestamp token created by {tsaCertificate.BaseName}, the dedicated timestamp-only TSA certificate.";
            pdfWriter.CreateSignedAndTimestampedPdf(timestampedPath, leaf, tsaCertificate, timestampedDescription);
        }

        // Valid append-mode sample with multiple detached CMS signatures created by different valid leaf certificates.
        var orderedLeafs = validLeafs.OrderBy(x => x.BaseName, StringComparer.Ordinal).Take(2).ToList();
        if (orderedLeafs.Count >= 2)
        {
            var multipleValidPath = Path.Combine(signedPdfsDirectory, "multiple-valid-signatures.pdf");
            var multipleValidDescription = $"PDF with two appended valid detached CMS signatures. Signature 1 uses {orderedLeafs[0].BaseName}. Signature 2 uses {orderedLeafs[1].BaseName}.";
            pdfWriter.CreatePdfWithMultipleValidSignatures(
                multipleValidPath,
                [
                    new ValidSignatureDescriptor(orderedLeafs[0], $"Valid detached CMS signature created with {orderedLeafs[0].BaseName}."),
                    new ValidSignatureDescriptor(orderedLeafs[1], $"Valid detached CMS signature created with {orderedLeafs[1].BaseName}.")
                ],
                multipleValidDescription);
        }
    }

    // The invalid set covers missing or unrelated signer EKUs, broken CMS payloads, broken timestamp semantics,
    // and multi-signature documents that combine valid and invalid signatures in append mode.
    private static void WriteInvalidPdfScenarios(
        string invalidPdfsDirectory,
        GeneratedCertificates certificates,
        PdfScenarioWriter pdfWriter)
    {
        // Invalid because the signer certificate has no EKU at all.
        var noEkuPath = Path.Combine(invalidPdfsDirectory, "signed-with-no-eku.pdf");
        var noEkuDescription = "Single detached CMS signature created with invalid-rsa-no-eku. The signature CMS is valid, but the signing certificate intentionally has neither the code-signing nor the time-stamping EKU.";
        pdfWriter.CreateSignedPdf(noEkuPath, certificates.InvalidNoEnhancedKeyUsage, noEkuDescription);

        // Invalid because the signer certificate uses an unrelated EKU instead of code signing.
        var differentEkuPath = Path.Combine(invalidPdfsDirectory, "signed-with-different-eku.pdf");
        var differentEkuDescription = "Single detached CMS signature created with invalid-rsa-different-eku. The signature CMS is valid, but the signing certificate uses an unrelated EKU instead of code signing.";
        pdfWriter.CreateSignedPdf(differentEkuPath, certificates.InvalidDifferentEnhancedKeyUsage, differentEkuDescription);

        // Valid control sample intentionally stored in the invalid folder so downstream verification can assert mixed outcomes.
        var controlPath = Path.Combine(invalidPdfsDirectory, "signed-valid-and-timestamped-control.pdf");
        var controlDescription = "Control sample requested by the spec: a single detached CMS signature created with rsa-leaf-valid and a valid RFC 3161 timestamp token created by rsa-tsa-leaf-valid. This file is intentionally valid even though it lives in pdfsInvalid.";
        pdfWriter.CreateSignedAndTimestampedPdf(controlPath, certificates.ControlLeaf, certificates.ValidTimestampAuthority, controlDescription);

        // Invalid because the PDF signature field contains bytes that are not a CMS object at all.
        var invalidCmsPath = Path.Combine(invalidPdfsDirectory, "signature-field-with-invalid-cms.pdf");
        var invalidCmsDescription = "PDF containing a signature field whose /Contents entry is deliberately filled with bytes that are not a valid CMS SignedData object.";
        pdfWriter.CreateInvalidCmsPdf(invalidCmsPath, invalidCmsDescription);

        // Invalid because the signature dictionary no longer exposes the /ByteRange entry, but the signature field itself remains readable.
        var missingByteRangePath = Path.Combine(invalidPdfsDirectory, "signature-field-with-missing-byte-range.pdf");
        var missingByteRangeDescription = "PDF containing a readable signature field whose detached CMS signature was created with rsa-leaf-valid and then had the /ByteRange key renamed so validation reports the byte range as missing.";
        pdfWriter.CreateSignedPdfWithMissingByteRange(missingByteRangePath, certificates.ControlLeaf, missingByteRangeDescription);

        // Invalid because the /ByteRange entry still exists but points to overlapping spans, making signature validation fail only when verified.
        var invalidByteRangePath = Path.Combine(invalidPdfsDirectory, "signature-field-with-invalid-byte-range.pdf");
        var invalidByteRangeDescription = "PDF containing a readable signature field whose detached CMS signature was created with rsa-leaf-valid and then had the /ByteRange values rewritten to overlapping offsets so validation reports the byte range as invalid.";
        pdfWriter.CreateSignedPdfWithInvalidByteRange(invalidByteRangePath, certificates.ControlLeaf, invalidByteRangeDescription);

        // Invalid because the RFC 3161 token is syntactically valid but signs the wrong message imprint.
        var invalidTimestampCmsPath = Path.Combine(invalidPdfsDirectory, "signed-valid-with-invalid-timestamp-cms.pdf");
        var invalidTimestampCmsDescription = "Single detached CMS signature created with rsa-leaf-valid and a well-formed RFC 3161 timestamp token created by rsa-tsa-leaf-valid over the wrong message imprint, making the timestamp semantically invalid.";
        pdfWriter.CreateSignedWithInvalidTimestampCmsPdf(invalidTimestampCmsPath, certificates.ControlLeaf, certificates.ValidTimestampAuthority, invalidTimestampCmsDescription);

        // Invalid because both appended signatures fail certificate-policy validation for different reasons.
        var multipleInvalidPath = Path.Combine(invalidPdfsDirectory, "multiple-invalid-signatures.pdf");
        var multipleInvalidDescription = "PDF with two appended detached CMS signatures and both are invalid for certificate-policy reasons. Signature 1 uses invalid-rsa-no-eku. Signature 2 uses invalid-rsa-different-eku.";
        pdfWriter.CreatePdfWithMultipleInvalidSignatures(
            multipleInvalidPath,
            [
                new InvalidSignatureDescriptor(
                    certificates.InvalidNoEnhancedKeyUsage,
                    "Detached CMS signature created with invalid-rsa-no-eku. The certificate has no EKU.",
                    InvalidSignatureKind.InvalidCertificate),
                new InvalidSignatureDescriptor(
                    certificates.InvalidDifferentEnhancedKeyUsage,
                    "Detached CMS signature created with invalid-rsa-different-eku. The certificate uses an unrelated EKU instead of code signing.",
                    InvalidSignatureKind.InvalidCertificate)
            ],
            multipleInvalidDescription);

        // Mixed result document with one valid signature followed by two invalid appended signatures.
        var mixedValidInvalidPath = Path.Combine(invalidPdfsDirectory, "mixed-valid-and-invalid-signatures.pdf");
        var mixedValidInvalidDescription = "PDF with three appended signatures: Signature 1 is valid and created with rsa-leaf-valid, Signature 2 is invalid because invalid-rsa-no-eku has no EKU, and Signature 3 is invalid because invalid-rsa-different-eku uses an unrelated EKU.";
        pdfWriter.CreatePdfWithValidAndInvalidSignatures(
            mixedValidInvalidPath,
            new ValidSignatureDescriptor(
                certificates.ControlLeaf,
                "Valid detached CMS signature created with rsa-leaf-valid."),
            [
                new InvalidSignatureDescriptor(
                    certificates.InvalidNoEnhancedKeyUsage,
                    "Detached CMS signature created with invalid-rsa-no-eku. The certificate has no EKU.",
                    InvalidSignatureKind.InvalidCertificate),
                new InvalidSignatureDescriptor(
                    certificates.InvalidDifferentEnhancedKeyUsage,
                    "Detached CMS signature created with invalid-rsa-different-eku. The certificate uses an unrelated EKU instead of code signing.",
                    InvalidSignatureKind.InvalidCertificate)
            ],
            mixedValidInvalidDescription);
    }
}
