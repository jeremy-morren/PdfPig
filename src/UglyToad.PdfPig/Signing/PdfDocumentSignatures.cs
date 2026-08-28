using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using UglyToad.PdfPig.AcroForms;
using UglyToad.PdfPig.AcroForms.Fields;
using UglyToad.PdfPig.Tokens;

namespace UglyToad.PdfPig.Signing;

using Core;

internal static class PdfSignatureVerifier
{
    private const string SigningTimeOid = "1.2.840.113549.1.9.5";
    private const string SignatureTimestampTokenOid = "1.2.840.113549.1.9.16.2.14";
    private const string SigningCertificateOid = "1.2.840.113549.1.9.16.2.12";
    private const string SigningCertificateV2Oid = "1.2.840.113549.1.9.16.2.47";
    private const string Sha1Oid = "1.3.14.3.2.26";
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

    /// <summary>
    /// Gets all embedded PDF signature results in stable AcroForm field-tree order.
    /// </summary>
    internal static List<PdfSignatureVerificationResult>? GetSignatures(
        AcroForm form,
        IInputBytes inputBytes,
        PdfSignatureVerificationOptions? options)
    {
        options ??= new PdfSignatureVerificationOptions();

        var parsedSignatures = GetParsedSignatures(form, inputBytes, options);

        return parsedSignatures.Count == 0
            ? null
            : parsedSignatures.Select(x => x.SignatureVerificationResult).ToList();
    }

    /// <summary>
    /// Gets all embedded RFC 3161 timestamp token results in stable AcroForm field-tree order.
    /// </summary>
    internal static List<PdfSignatureVerificationResult>? GetTimestampSignatures(
        AcroForm form,
        IInputBytes inputBytes,
        PdfSignatureVerificationOptions? options)
    {
        options ??= new PdfSignatureVerificationOptions();

        var parsedSignatures = GetParsedSignatures(form, inputBytes, options);
        if (parsedSignatures.Count == 0)
        {
            return null;
        }

        var results = new List<PdfSignatureVerificationResult>();

        foreach (var parsedSignature in parsedSignatures)
        {
            if (parsedSignature.SignerInfo is null || parsedSignature.SignerSignature is null)
            {
                continue;
            }

            var signerTimestampResults = GetTimestampResults(parsedSignature, options);
            if (signerTimestampResults.Count > 0)
            {
                results.AddRange(signerTimestampResults);
            }
        }

        return results.Count == 0 ? null : results;
    }

    private static List<ParsedPdfSignature> GetParsedSignatures(
        AcroForm form,
        IInputBytes inputBytes,
        PdfSignatureVerificationOptions options)
    {
        var result = new List<ParsedPdfSignature>();
        foreach (var field in form.GetFields().OfType<AcroSignatureField>())
        {
            if (field.SignatureValue is null)
            {
                continue;
            }

            var signature = VerifySignatureField(field, field.SignatureValue, inputBytes, options);
            result.Add(signature);
        }

        FlagContentAppendedAfterSigning(result, inputBytes.Length);
        return result;
    }

    /// <summary>
    /// Marks otherwise valid signatures that leave trailing bytes uncovered.
    /// </summary>
    /// <remarks>
    /// A signature covering less than the whole file is normal in a multiply-signed document, because
    /// each later signature appends a revision the earlier ones cannot include. It is only benign when
    /// some other signature reaches further into the file. When the outermost signature stops short of
    /// the end, the remaining bytes were appended after every signature was applied and nothing vouches
    /// for them, so reporting those signatures as valid would let a caller checking only
    /// <see cref="PdfSignatureVerificationResult.IsValid"/> trust unsigned content.
    /// </remarks>
    private static void FlagContentAppendedAfterSigning(List<ParsedPdfSignature> signatures, long documentLength)
    {
        var furthestCoverage = 0L;

        foreach (var signature in signatures)
        {
            if (signature.CoverageExtent > furthestCoverage)
            {
                furthestCoverage = signature.CoverageExtent.GetValueOrDefault();
            }
        }

        if (furthestCoverage >= documentLength)
        {
            return;
        }

        for (var i = 0; i < signatures.Count; i++)
        {
            var signature = signatures[i];
            var result = signature.SignatureVerificationResult;

            // Signatures already reporting a failure keep their more specific error, and a signature
            // superseded by one that reaches further into the file is covered by that later signature.
            if (!result.IsValid || signature.CoverageExtent != furthestCoverage)
            {
                continue;
            }

            signatures[i] = signature.WithResult(new PdfSignatureVerificationResult(
                PdfSignatureError.DocumentModifiedAfterSigning,
                result.FieldName,
                $"The document contains {documentLength - furthestCoverage} bytes appended after this signature was applied.",
                result.Certificate,
                result.SigningTime,
                result.TimeStampTime,
                result.CoversEntireDocument,
                result.SubFilter));
        }
    }


    private static ParsedPdfSignature VerifySignatureField(
        AcroSignatureField signatureField,
        AcroSignatureValue signatureValue,
        IInputBytes pdfBytes,
        PdfSignatureVerificationOptions options)
    {
        var fieldName = signatureField.Information.FullyQualifiedName ?? signatureField.Information.PartialName;
        var subFilter = GetSubFilter(signatureValue.SubFilter);

        // Everything below shares the field name and subfilter, and from the byte range onwards the
        // coverage facts too, so results are built through these rather than repeating them.
        var coversEntireDocument = false;
        long? coverageExtent = null;

        ParsedPdfSignature Invalid(
            PdfSignatureError error,
            string message,
            X509Certificate2? certificate = null,
            DateTimeOffset? signingTime = null,
            PdfCertificateValidationFailedException? validationException = null) =>
            ParsedPdfSignature.FromResult(
                new PdfSignatureVerificationResult(
                    error, fieldName, message, certificate, signingTime, null,
                    coversEntireDocument, subFilter, validationException),
                coverageExtent);

        if (!IsSupported(subFilter))
        {
            return Invalid(
                PdfSignatureError.UnsupportedSubFilter,
                $"Unsupported signature subfilter: {signatureValue.SubFilter ?? "<missing>"}.");
        }

        if (!TryGetByteRange(signatureValue, pdfBytes.Length, out var byteRange, out var byteRangeErrorMessage))
        {
            return Invalid(
                byteRangeErrorMessage is null ? PdfSignatureError.ByteRangeMissing : PdfSignatureError.ByteRangeInvalid,
                byteRangeErrorMessage ?? "The signature dictionary does not contain a /ByteRange entry.");
        }

        if (!TryGetContentsBytes(signatureValue, out var contentsBytes, out var contentsError))
        {
            return Invalid(
                contentsError ?? PdfSignatureError.ContentsMissing,
                "The signature dictionary does not contain usable CMS contents.");
        }

        // The span excluded by /ByteRange must be exactly the /Contents value as it appears in the file.
        // Checking only that the gap is the right size would let a document exclude a span unrelated to
        // the CMS payload being verified, leaving room for unsigned content to hide inside the gap.
        if (!byteRange.ExcludedSpanMatchesContents(pdfBytes, contentsBytes, signatureValue.ContentsFieldValueLength))
        {
            return Invalid(
                PdfSignatureError.ByteRangeInvalid,
                "The /ByteRange entry does not exclude exactly the /Contents value.");
        }

        coversEntireDocument = byteRange.CoversEntireDocument(pdfBytes.Length);

        // The byte range is now known to delimit the /Contents value, so how far it reaches into the
        // file is trustworthy even if the signature itself later fails to verify. Failures below still
        // report this extent so a later revision can be recognised as covering an earlier signature.
        coverageExtent = byteRange.Offset2 + byteRange.Length2;

        var signedContent = byteRange.ReadSignedContent(pdfBytes);

        if (!TryDecodeSignedCms(contentsBytes, signedContent, out var cms, out var cmsBytes))
        {
            return Invalid(PdfSignatureError.CmsInvalid, "The CMS payload could not be decoded.");
        }

        if (cms.SignerInfos.Count == 0)
        {
            return Invalid(PdfSignatureError.SigningCertificateMissing, "The CMS payload did not contain a signer.");
        }

        var signerInfo = cms.SignerInfos[0];
        var cmsSigningTime = GetSigningTime(signerInfo);

        try
        {
            signerInfo.CheckSignature(true);
        }
        catch (CryptographicException)
        {
            return Invalid(
                PdfSignatureError.SignatureMismatch,
                "The CMS signature did not validate against the PDF byte ranges.",
                signerInfo.Certificate, cmsSigningTime);
        }

        var signingCertificate = signerInfo.Certificate;
        if (signingCertificate is null)
        {
            return Invalid(
                PdfSignatureError.SigningCertificateMissing,
                "The CMS payload did not expose a signing certificate.",
                null, cmsSigningTime);
        }

        // CAdES requires the signed attributes to commit to the signing certificate, which stops a
        // signature being re-presented with a different certificate carrying the same key. The
        // attribute is honoured wherever it appears, but only demanded where the profile demands it.
        var signingCertificateAttributeError = ValidateSigningCertificateAttribute(
            signerInfo,
            signingCertificate,
            required: subFilter == PdfSignatureSubFilter.CAdESDetached);

        if (signingCertificateAttributeError is not null)
        {
            return Invalid(PdfSignatureError.CmsInvalid, signingCertificateAttributeError, signingCertificate, cmsSigningTime);
        }

        if (TryRunCertificateValidator(options.SignatureCertificateValidator, signingCertificate, subFilter, out var validatorException))
        {
            return Invalid(
                PdfSignatureError.CertificateValidationFailed,
                validatorException!.Message,
                signingCertificate, cmsSigningTime, validatorException);
        }

        if (!TryGetSignerSignature(cmsBytes, out var signerSignature))
        {
            return Invalid(
                PdfSignatureError.CmsInvalid,
                "The CMS payload did not expose a signer signature value.",
                signingCertificate, cmsSigningTime);
        }

        // The CMS signing time is a claim made by the signer's own key, so it cannot decide when the
        // chain is validated: a holder of an expired or revoked certificate could otherwise backdate it
        // and be trusted. Only an RFC 3161 token from a trusted authority establishes an earlier moment;
        // without one the chain is validated as of now.
        var trustedTime = GetTrustedTimeStampTime(signerInfo, signerSignature, subFilter, options);

        var chainError = ValidateCertificate(signingCertificate,
            cms.Certificates,
            options.SignatureTrust,
            trustedTime,
            PdfSignatureError.SigningCertificateNotTrusted,
            PdfSignatureError.SigningCertificateRevoked,
            PdfSignatureError.SigningCertificateExpired);
        if (chainError is not null)
        {
            return Invalid(
                chainError.Value,
                $"The signing certificate could not be trusted: {chainError.Value}.",
                signingCertificate, cmsSigningTime);
        }

        return new ParsedPdfSignature(
            new PdfSignatureVerificationResult(
                null, fieldName, "The signature is valid.", signingCertificate, cmsSigningTime, null,
                coversEntireDocument, subFilter),
            cms,
            signerInfo,
            signerSignature,
            cmsSigningTime,
            fieldName,
            coverageExtent,
            subFilter);
    }

    private static PdfSignatureSubFilter GetSubFilter(string? subFilter) => subFilter switch
    {
        "adbe.pkcs7.detached" => PdfSignatureSubFilter.Pkcs7Detached,
        "ETSI.CAdES.detached" => PdfSignatureSubFilter.CAdESDetached,
        "adbe.pkcs7.sha1" => PdfSignatureSubFilter.Pkcs7Sha1,
        "adbe.x509.rsa_sha1" => PdfSignatureSubFilter.X509RsaSha1,
        "ETSI.RFC3161" => PdfSignatureSubFilter.DocumentTimeStamp,
        _ => PdfSignatureSubFilter.Unknown
    };

    /// <summary>
    /// Both supported subfilters carry a detached CMS signature over the byte ranges and are verified
    /// the same way, differing only in whether the signing-certificate attribute is mandatory.
    /// </summary>
    private static bool IsSupported(PdfSignatureSubFilter subFilter) =>
        subFilter is PdfSignatureSubFilter.Pkcs7Detached or PdfSignatureSubFilter.CAdESDetached;

    /// <summary>
    /// Runs a certificate validator, returning <see langword="true"/> when it rejected the certificate.
    /// </summary>
    private static bool TryRunCertificateValidator(
        ICertificateValidator? validator,
        X509Certificate2 certificate,
        PdfSignatureSubFilter subFilter,
        out PdfCertificateValidationFailedException? exception)
    {
        exception = null;

        if (validator is null)
        {
            return false;
        }

        try
        {
            validator.ValidateCertificate(certificate, subFilter);
            return false;
        }
        catch (PdfCertificateValidationFailedException ex)
        {
            exception = ex;
            return true;
        }
    }

    /// <summary>
    /// Verifies the ESS signing-certificate signed attribute, which binds the certificate the signer
    /// intended into the signed data. Returns an error message, or <see langword="null"/> when the
    /// attribute is absent and not required, or present and correct.
    /// </summary>
    private static string? ValidateSigningCertificateAttribute(
        SignerInfo signerInfo,
        X509Certificate2 certificate,
        bool required)
    {
        foreach (var attribute in signerInfo.SignedAttributes)
        {
            var isV2 = string.Equals(attribute.Oid.Value, SigningCertificateV2Oid, StringComparison.Ordinal);

            if (!isV2 && !string.Equals(attribute.Oid.Value, SigningCertificateOid, StringComparison.Ordinal))
            {
                continue;
            }

            if (attribute.Values.Count == 0)
            {
                return "The signing certificate attribute is empty.";
            }

            if (!TryReadSigningCertificateHash(attribute.Values[0].RawData, isV2, out var algorithmOid, out var expectedHash))
            {
                return "The signing certificate attribute could not be decoded.";
            }

            if (!TryComputeDigest(algorithmOid, certificate.RawData, out var actualHash))
            {
                return $"Unsupported signing certificate attribute digest algorithm: {algorithmOid}.";
            }

            return expectedHash.AsSpan().SequenceEqual(actualHash)
                ? null
                : "The signing certificate attribute does not match the certificate that signed the document.";
        }

        return required
            ? "The signature does not carry the signing certificate attribute its subfilter requires."
            : null;
    }

    /// <summary>
    /// Reads the first certificate hash out of an ESS <c>SigningCertificate</c> or
    /// <c>SigningCertificateV2</c> attribute value.
    /// </summary>
    private static bool TryReadSigningCertificateHash(
        byte[] rawAttributeValue,
        bool isV2,
        out string algorithmOid,
        [NotNullWhen(true)] out byte[]? hash)
    {
        // SigningCertificate[V2] ::= SEQUENCE { certs SEQUENCE OF ESSCertID[V2], policies ... OPTIONAL }
        // ESSCertID              ::= SEQUENCE { certHash OCTET STRING, issuerSerial ... OPTIONAL }
        // ESSCertIDv2            ::= SEQUENCE { hashAlgorithm ... DEFAULT sha256, certHash OCTET STRING, ... }
        algorithmOid = Sha1Oid;
        hash = null;

        try
        {
            var certs = new AsnReader(rawAttributeValue, AsnEncodingRules.BER).ReadSequence().ReadSequence();
            var certId = certs.ReadSequence();

            if (isV2)
            {
                // The algorithm identifier is omitted when it is the SHA-256 default, in which case the
                // first element is the hash itself.
                if (certId.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
                {
                    var algorithm = certId.ReadSequence();
                    algorithmOid = algorithm.ReadObjectIdentifier();
                }
                else
                {
                    algorithmOid = Sha256Oid;
                }
            }

            hash = certId.ReadOctetString();
            return true;
        }
        catch (AsnContentException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// Returns the generation time of the first embedded RFC 3161 token that both commits to this
    /// signature value and builds to a trusted timestamp authority, or <see langword="null"/> when the
    /// signature carries no such token.
    /// </summary>
    private static DateTimeOffset? GetTrustedTimeStampTime(
        SignerInfo signerInfo,
        byte[] signerSignature,
        PdfSignatureSubFilter subFilter,
        PdfSignatureVerificationOptions options)
    {
        foreach (var unsignedAttribute in signerInfo.UnsignedAttributes)
        {
            if (!string.Equals(unsignedAttribute.Oid.Value, SignatureTimestampTokenOid, StringComparison.Ordinal))
            {
                continue;
            }

            foreach (var value in unsignedAttribute.Values)
            {
                if (TryGetVerifiedTimeStampTime(value.RawData, signerSignature, subFilter, options, out var generationTime))
                {
                    return generationTime;
                }
            }
        }

        return null;
    }

    private static bool TryGetVerifiedTimeStampTime(
        byte[] rawTimestampToken,
        byte[] signerSignature,
        PdfSignatureSubFilter subFilter,
        PdfSignatureVerificationOptions options,
        out DateTimeOffset generationTime)
    {
        generationTime = default;

        SignedCms timestampCms;

        try
        {
            timestampCms = new SignedCms();
            timestampCms.Decode(rawTimestampToken);

            if (timestampCms.SignerInfos.Count == 0)
            {
                return false;
            }

            timestampCms.CheckSignature(true);
        }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException)
        {
            return false;
        }

        if (!TryParseTimestampInfo(timestampCms.ContentInfo.Content, out var timestampInfo) ||
            !TryComputeDigest(timestampInfo.HashAlgorithmOid, signerSignature, out var expectedMessageImprint) ||
            !timestampInfo.MessageImprint.AsSpan().SequenceEqual(expectedMessageImprint))
        {
            return false;
        }

        var timestampCertificate = timestampCms.SignerInfos[0].Certificate;

        if (timestampCertificate is null ||
            TryRunCertificateValidator(options.TimeStampCertificateValidator, timestampCertificate, subFilter, out _))
        {
            return false;
        }

        // The authority's chain is validated as of the moment it issued the token, which is what a
        // timestamp is for: the certificate is expected to age out while the token stays meaningful.
        var chainError = ValidateCertificate(
            timestampCertificate,
            timestampCms.Certificates,
            options.TimeStampTrust,
            timestampInfo.GenerationTime,
            PdfSignatureError.TimeStampCertificateNotTrusted,
            PdfSignatureError.TimeStampCertificateRevoked,
            PdfSignatureError.TimeStampCertificateExpired);

        if (chainError is not null)
        {
            return false;
        }

        generationTime = timestampInfo.GenerationTime;
        return true;
    }

    private static List<PdfSignatureVerificationResult> GetTimestampResults(
        ParsedPdfSignature parsedSignature, PdfSignatureVerificationOptions options)
    {
        var results = new List<PdfSignatureVerificationResult>();

        foreach (var unsignedAttribute in parsedSignature.SignerInfo!.UnsignedAttributes)
        {
            if (!string.Equals(unsignedAttribute.Oid.Value, SignatureTimestampTokenOid, StringComparison.Ordinal))
            {
                continue;
            }

            foreach (var value in unsignedAttribute.Values)
            {
                results.Add(VerifyTimestampToken(parsedSignature, value.RawData, options));
            }
        }

        return results;
    }

    private static PdfSignatureVerificationResult VerifyTimestampToken(
        ParsedPdfSignature parsedSignature, byte[] rawTimestampToken, PdfSignatureVerificationOptions options)
    {
        var coversEntireDocument = parsedSignature.SignatureVerificationResult.CoversEntireDocument;

        SignedCms timestampCms;

        try
        {
            timestampCms = new SignedCms();
            timestampCms.Decode(rawTimestampToken);
        }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException)
        {
            return CreateInvalidResult(
                PdfSignatureError.TimeStampTokenInvalid,
                parsedSignature.FieldName,
                "The RFC 3161 timestamp token could not be decoded.",
                null, parsedSignature.SigningTime,
                coversEntireDocument: coversEntireDocument);
        }

        if (timestampCms.SignerInfos.Count == 0)
        {
            return CreateInvalidResult(
                PdfSignatureError.TimeStampCertificateMissing,
                parsedSignature.FieldName,
                "The RFC 3161 timestamp token does not contain a signer.",
                null, parsedSignature.SigningTime,
                coversEntireDocument: coversEntireDocument);
        }

        var timestampSigner = timestampCms.SignerInfos[0];

        try
        {
            timestampCms.CheckSignature(true);
        }
        catch (CryptographicException)
        {
            return CreateInvalidResult(
                PdfSignatureError.TimeStampTokenInvalid,
                parsedSignature.FieldName,
                "The RFC 3161 timestamp signature is invalid.",
                timestampSigner.Certificate, parsedSignature.SigningTime,
                coversEntireDocument: coversEntireDocument);
        }

        if (!TryParseTimestampInfo(timestampCms.ContentInfo.Content, out var timestampInfo))
        {
            return CreateInvalidResult(
                PdfSignatureError.TimeStampTokenInvalid,
                parsedSignature.FieldName,
                "The RFC 3161 timestamp content could not be parsed.",
                timestampSigner.Certificate, parsedSignature.SigningTime,
                coversEntireDocument: coversEntireDocument);
        }

        if (!TryComputeDigest(timestampInfo.HashAlgorithmOid, parsedSignature.SignerSignature!, out var expectedMessageImprint))
        {
            return CreateInvalidResult(
                PdfSignatureError.TimeStampTokenInvalid,
                parsedSignature.FieldName,
                $"Unsupported timestamp digest algorithm: {timestampInfo.HashAlgorithmOid}.",
                timestampSigner.Certificate, parsedSignature.SigningTime, timestampInfo.GenerationTime,
                coversEntireDocument);
        }

        if (!timestampInfo.MessageImprint.AsSpan().SequenceEqual(expectedMessageImprint))
        {
            return CreateInvalidResult(
                PdfSignatureError.TimeStampTokenMismatch,
                parsedSignature.FieldName,
                "The RFC 3161 timestamp token does not match the CMS signature value.",
                timestampSigner.Certificate, parsedSignature.SigningTime, timestampInfo.GenerationTime,
                coversEntireDocument);
        }

        var timestampCertificate = timestampSigner.Certificate;
        if (timestampCertificate is null)
        {
            return CreateInvalidResult(
                PdfSignatureError.TimeStampCertificateMissing,
                parsedSignature.FieldName,
                "The RFC 3161 timestamp token did not expose a TSA certificate.",
                null, parsedSignature.SigningTime, timestampInfo.GenerationTime,
                coversEntireDocument);
        }

        if (TryRunCertificateValidator(
                options.TimeStampCertificateValidator, timestampCertificate, parsedSignature.SubFilter, out var validatorException))
        {
            return CreateInvalidResult(
                PdfSignatureError.CertificateValidationFailed,
                parsedSignature.FieldName,
                validatorException!.Message,
                timestampCertificate, parsedSignature.SigningTime, timestampInfo.GenerationTime,
                coversEntireDocument, parsedSignature.SubFilter, validatorException);
        }

        // As of the moment the token was issued: a timestamp is expected to outlive the authority's
        // certificate, so validating it as of now would reject every archived timestamp.
        var chainError = ValidateCertificate(
            timestampCertificate, timestampCms.Certificates, options.TimeStampTrust, timestampInfo.GenerationTime,
            PdfSignatureError.TimeStampCertificateNotTrusted, PdfSignatureError.TimeStampCertificateRevoked, PdfSignatureError.TimeStampCertificateExpired);
        if (chainError is not null)
        {
            return CreateInvalidResult(chainError.Value,
                parsedSignature.FieldName,
                $"The TSA certificate could not be trusted: {chainError.Value}.",
                timestampCertificate, parsedSignature.SigningTime, timestampInfo.GenerationTime,
                coversEntireDocument);
        }

        if (parsedSignature.SigningTime.HasValue && timestampInfo.GenerationTime < parsedSignature.SigningTime.Value)
        {
            return CreateInvalidResult(
                PdfSignatureError.TimeStampBeforeSigning,
                parsedSignature.FieldName,
                "The RFC 3161 timestamp time precedes the CMS signing time.",
                timestampCertificate, parsedSignature.SigningTime, timestampInfo.GenerationTime,
                coversEntireDocument);
        }

        return CreateValidResult(
            parsedSignature.FieldName,
            "The RFC 3161 timestamp token is valid.",
            timestampCertificate, parsedSignature.SigningTime, timestampInfo.GenerationTime,
            coversEntireDocument);
    }

    private static bool TryParseTimestampInfo(ReadOnlyMemory<byte> content, [NotNullWhen(true)] out TimestampInfo? timestampInfo)
    {
        timestampInfo = null;

        try
        {
            var reader = new AsnReader(content, AsnEncodingRules.BER);
            var sequence = reader.ReadSequence();
            sequence.ReadInteger();
            sequence.ReadObjectIdentifier();

            var messageImprintSequence = sequence.ReadSequence();
            var algorithmIdentifier = messageImprintSequence.ReadSequence();
            var algorithmOid = algorithmIdentifier.ReadObjectIdentifier();
            if (algorithmIdentifier.HasData)
            {
                algorithmIdentifier.ReadEncodedValue();
            }

            var messageImprint = messageImprintSequence.ReadOctetString();
            sequence.ReadInteger();
            var generationTime = sequence.ReadGeneralizedTime();

            timestampInfo = new TimestampInfo(algorithmOid, messageImprint, generationTime);
            return true;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private static bool TryComputeDigest(string algorithmOid, byte[] data, [NotNullWhen(true)] out byte[]? digest)
    {
        using HashAlgorithm? hashAlgorithm = algorithmOid switch
        {
            "1.3.14.3.2.26" => SHA1.Create(),
            "2.16.840.1.101.3.4.2.1" => SHA256.Create(),
            "2.16.840.1.101.3.4.2.2" => SHA384.Create(),
            "2.16.840.1.101.3.4.2.3" => SHA512.Create(),
            _ => null
        };

        if (hashAlgorithm is null)
        {
            digest = null;
            return false;
        }

        digest = hashAlgorithm.ComputeHash(data);
        return true;
    }

    private static bool TryDecodeSignedCms(
        byte[] contentsBytes,
        byte[] signedContent,
        [NotNullWhen(true)] out SignedCms? cms,
        [NotNullWhen(true)] out byte[]? decodedBytes)
    {
        cms = null;
        decodedBytes = null;
        return TryExtractCmsBytes(contentsBytes, out decodedBytes) &&
               TryDecodeSignedCms(decodedBytes, signedContent, out cms);
    }

    private static bool TryDecodeSignedCms(
        byte[] cmsBytes, byte[] signedContent, [NotNullWhen(true)] out SignedCms? cms)
    {
        cms = null;

        try
        {
            cms = new SignedCms(new ContentInfo(signedContent), detached: true);
            cms.Decode(cmsBytes);
            return true;
        }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException)
        {
            return false;
        }
    }

    private static bool TryExtractCmsBytes(byte[] contentsBytes, [NotNullWhen(true)] out byte[]? cmsBytes)
    {
        cmsBytes = null;

        try
        {
            var reader = new AsnReader(contentsBytes, AsnEncodingRules.BER);
            var encodedValue = reader.ReadEncodedValue();
            var encodedLength = encodedValue.Length;

            if (encodedLength < contentsBytes.Length)
            {
                for (var i = encodedLength; i < contentsBytes.Length; i++)
                {
                    if (contentsBytes[i] != 0)
                    {
                        return false;
                    }
                }

                cmsBytes = encodedValue.ToArray();
                return true;
            }

            cmsBytes = contentsBytes;
            return true;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private static bool TryGetSignerSignature(ReadOnlyMemory<byte> cmsBytes, [NotNullWhen(true)] out byte[]? signature)
    {
        signature = null;

        try
        {
            var contentInfo = new AsnReader(cmsBytes, AsnEncodingRules.BER).ReadSequence();
            contentInfo.ReadObjectIdentifier();

            var signedDataWrapper = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            var signedData = signedDataWrapper.ReadSequence();

            signedData.ReadInteger();
            signedData.ReadSetOf();
            signedData.ReadSequence();

            while (signedData.HasData)
            {
                var nextTag = signedData.PeekTag();
                if (nextTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0))
                    || nextTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
                {
                    signedData.ReadEncodedValue();
                    continue;
                }

                break;
            }

            var signerInfos = signedData.ReadSetOf();
            var signerInfo = signerInfos.ReadSequence();
            signerInfo.ReadInteger();

            var signerIdentifierTag = signerInfo.PeekTag();
            if (signerIdentifierTag.TagClass == TagClass.ContextSpecific)
            {
                signerInfo.ReadEncodedValue();
            }
            else
            {
                signerInfo.ReadSequence();
            }

            signerInfo.ReadSequence();

            if (signerInfo.HasData && signerInfo.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                signerInfo.ReadEncodedValue();
            }

            signerInfo.ReadSequence();
            signature = signerInfo.ReadOctetString();
            return true;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private static PdfSignatureError? ValidateCertificate(
        X509Certificate2 certificate,
        X509Certificate2Collection availableCertificates,
        PdfCertificateTrustOptions trustOptions,
        DateTimeOffset? verificationTime,
        PdfSignatureError notTrustedError,
        PdfSignatureError revokedError,
        PdfSignatureError expiredError)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = trustOptions.RevocationMode;
        chain.ChainPolicy.RevocationFlag = trustOptions.RevocationFlag;
        chain.ChainPolicy.VerificationFlags = trustOptions.VerificationFlags;

        if (!trustOptions.UseSystemStore)
        {
            if (trustOptions.AdditionalTrustedRoots.Count == 0)
            {
                return notTrustedError;
            }
#if NET
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            foreach (var trustedRoot in trustOptions.AdditionalTrustedRoots)
            {
                chain.ChainPolicy.CustomTrustStore.Add(trustedRoot);
            }
#else
            foreach (var trustedRoot in trustOptions.AdditionalTrustedRoots)
            {
                chain.ChainPolicy.ExtraStore.Add(trustedRoot);
            }
#endif
        }

        if (verificationTime.HasValue)
        {
            chain.ChainPolicy.VerificationTime = verificationTime.Value.LocalDateTime;
        }

        foreach (var availableCertificate in availableCertificates)
        {
            if (!HasSameThumbprint(availableCertificate, certificate))
            {
                chain.ChainPolicy.ExtraStore.Add(availableCertificate);
            }
        }

        foreach (var intermediateCertificate in trustOptions.AdditionalIntermediateCertificates)
        {
            chain.ChainPolicy.ExtraStore.Add(intermediateCertificate);
        }

        foreach (var trustedRoot in trustOptions.AdditionalTrustedRoots)
        {
            chain.ChainPolicy.ExtraStore.Add(trustedRoot);
        }

        var buildSucceeded = chain.Build(certificate);

        var statuses = chain.ChainStatus.Select(x => x.Status).Where(x => x != X509ChainStatusFlags.NoError).ToList();

        if (statuses.Any(x => (x & X509ChainStatusFlags.Revoked) != 0))
        {
            return revokedError;
        }

        if (statuses.Any(x => (x & (X509ChainStatusFlags.NotTimeValid | X509ChainStatusFlags.NotTimeNested)) != 0))
        {
            return expiredError;
        }

        if (buildSucceeded && statuses.Count == 0)
        {
            return null;
        }

        if (!TryGetTrustedChainRoot(chain, out var chainRoot))
        {
            return notTrustedError;
        }

        if (!trustOptions.UseSystemStore)
        {
            if (trustOptions.AdditionalTrustedRoots.Count == 0 ||
                !trustOptions.AdditionalTrustedRoots.Any(x => HasSameThumbprint(x, chainRoot)) ||
                statuses.Any(x => (x & ~(X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain)) != 0))
            {
                return notTrustedError;
            }

            return null;
        }

        if (statuses.Count == 0)
        {
            return null;
        }

        if (trustOptions.AdditionalTrustedRoots.Any(x => HasSameThumbprint(x, chainRoot))
            && statuses.All(x => (x & ~(X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain)) == 0))
        {
            return null;
        }

        return notTrustedError;
    }

    private static bool TryGetTrustedChainRoot(X509Chain chain, [NotNullWhen(true)] out X509Certificate2? certificate)
    {
        certificate = null;

        if (chain.ChainElements.Count == 0)
        {
            return false;
        }

        certificate = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
        return true;
    }

    private static bool HasSameThumbprint(X509Certificate2 left, X509Certificate2 right) =>
        string.Equals(left.Thumbprint, right.Thumbprint, StringComparison.OrdinalIgnoreCase);

    private static DateTimeOffset? GetSigningTime(SignerInfo signerInfo)
    {
        foreach (var signedAttribute in signerInfo.SignedAttributes)
        {
            if (!string.Equals(signedAttribute.Oid.Value, SigningTimeOid, StringComparison.Ordinal) ||
                signedAttribute.Values.Count == 0)
            {
                continue;
            }

            try
            {
                return new Pkcs9SigningTime(signedAttribute.Values[0].RawData).SigningTime;
            }
            catch (CryptographicException)
            {
                break;
            }
        }

        return null;
    }


    private static bool TryGetContentsBytes(AcroSignatureValue signatureValue, [NotNullWhen(true)] out byte[]? contentsBytes, out PdfSignatureError? error)
    {
        contentsBytes = null;
        error = null;

        if (!signatureValue.Dictionary.TryGet(NameToken.Contents, out var contentsToken))
        {
            error = PdfSignatureError.ContentsMissing;
            return false;
        }

        switch (contentsToken)
        {
            case HexToken hexToken:
                contentsBytes = hexToken.Memory.ToArray();
                return true;
            case StringToken stringToken:
                contentsBytes = stringToken.GetBytes();
                return true;
            default:
                error = PdfSignatureError.ContentsInvalid;
                return false;
        }
    }

    private static bool TryGetByteRange(AcroSignatureValue signatureValue, long documentLength, out SignatureByteRange byteRange, out string? errorMessage)
    {
        byteRange = default;
        errorMessage = null;

        if (!signatureValue.Dictionary.TryGet(NameToken.Byterange, out ArrayToken byteRangeToken))
        {
            return false;
        }

        if (byteRangeToken.Length != 4
            || byteRangeToken[0] is not NumericToken offset1Token
            || byteRangeToken[1] is not NumericToken length1Token
            || byteRangeToken[2] is not NumericToken offset2Token
            || byteRangeToken[3] is not NumericToken length2Token)
        {
            errorMessage = "The /ByteRange entry must contain exactly four numeric values.";
            return false;
        }

        var offset1 = offset1Token.Long;
        var length1Value = length1Token.Long;
        var offset2 = offset2Token.Long;
        var length2Value = length2Token.Long;

        if (length1Value > int.MaxValue || length2Value > int.MaxValue)
        {
            errorMessage = "The /ByteRange entry contains invalid offsets or lengths.";
            return false;
        }

        var length1 = (int)length1Value;
        var length2 = (int)length2Value;

        if (offset1 < 0 || length1Value < 0 || offset2 < 0 || length2Value < 0)
        {
            errorMessage = "The /ByteRange entry contains invalid offsets or lengths.";
            return false;
        }

        if (offset1 + length1 > offset2 || offset2 + length2 > documentLength)
        {
            errorMessage = "The /ByteRange entry points outside the document or overlaps the excluded contents span.";
            return false;
        }

        byteRange = new SignatureByteRange(offset1, length1, offset2, length2);
        return true;
    }

    private static PdfSignatureVerificationResult CreateInvalidResult(
        PdfSignatureError error,
        string? fieldName,
        string message,
        X509Certificate2? certificate = null,
        DateTimeOffset? signingTime = null,
        DateTimeOffset? timestampTime = null,
        bool coversEntireDocument = false,
        PdfSignatureSubFilter subFilter = PdfSignatureSubFilter.Unknown,
        PdfCertificateValidationFailedException? certificateValidationException = null)
    {
        return new PdfSignatureVerificationResult(
            error, fieldName, message, certificate, signingTime, timestampTime, coversEntireDocument,
            subFilter, certificateValidationException);
    }

    private static PdfSignatureVerificationResult CreateValidResult(
        string? fieldName,
        string message,
        X509Certificate2? certificate,
        DateTimeOffset? signingTime,
        DateTimeOffset? timestampTime,
        bool coversEntireDocument = false,
        PdfSignatureSubFilter subFilter = PdfSignatureSubFilter.Unknown)
    {
        return new PdfSignatureVerificationResult(
            null, fieldName, message, certificate, signingTime, timestampTime, coversEntireDocument, subFilter);
    }

    private readonly record struct SignatureByteRange(long Offset1, int Length1, long Offset2, int Length2)
    {
        public bool CoversEntireDocument(long documentLength)
        {
            // The excluded span is separately verified to be exactly the /Contents value, so the
            // document is fully covered when the signed spans run from the first byte to the last.
            return Offset1 == 0 && Offset2 + Length2 == documentLength;
        }

        /// <summary>
        /// Checks that the bytes skipped between the two signed spans are exactly the <c>/Contents</c>
        /// value, delimiters included, and that they encode <paramref name="contents"/>.
        /// </summary>
        public bool ExcludedSpanMatchesContents(IInputBytes inputBytes, ReadOnlySpan<byte> contents, int contentsFieldValueLength)
        {
            var start = Offset1 + Length1;
            var length = Offset2 - start;

            if (length < 2 || length > int.MaxValue)
            {
                return false;
            }

            var excluded = new byte[(int)length];
            var originalOffset = inputBytes.CurrentOffset;

            try
            {
                inputBytes.Seek(start);
                if (inputBytes.Read(excluded) != excluded.Length)
                {
                    return false;
                }
            }
            finally
            {
                inputBytes.Seek(originalOffset);
            }

            var span = TrimWhitespace(excluded);

            if (span.Length < 2)
            {
                return false;
            }

            if (span[0] == '<' && span[span.Length - 1] == '>')
            {
                return HexDigitsMatch(span.Slice(1, span.Length - 2), contents);
            }

            // Literal string contents are vanishingly rare and their escape rules make an exact
            // comparison impractical here, so fall back to the length recorded when the token was read.
            if (span[0] == '(' && span[span.Length - 1] == ')')
            {
                return span.Length == contentsFieldValueLength;
            }

            return false;
        }

        private static ReadOnlySpan<byte> TrimWhitespace(ReadOnlySpan<byte> value)
        {
            var start = 0;
            var end = value.Length;

            while (start < end && ReadHelper.IsWhitespace(value[start]))
            {
                start++;
            }

            while (end > start && ReadHelper.IsWhitespace(value[end - 1]))
            {
                end--;
            }

            return value.Slice(start, end - start);
        }

        private static bool HexDigitsMatch(ReadOnlySpan<byte> hexDigits, ReadOnlySpan<byte> expected)
        {
            var index = 0;
            var highNibble = -1;

            foreach (var value in hexDigits)
            {
                if (ReadHelper.IsWhitespace(value))
                {
                    continue;
                }

                var nibble = GetHexNibble(value);
                if (nibble < 0)
                {
                    return false;
                }

                if (highNibble < 0)
                {
                    highNibble = nibble;
                    continue;
                }

                if (index >= expected.Length || expected[index] != (byte)((highNibble << 4) | nibble))
                {
                    return false;
                }

                index++;
                highNibble = -1;
            }

            if (highNibble >= 0)
            {
                // A trailing odd hex digit is treated as if followed by a zero, as per 7.3.4.3.
                if (index >= expected.Length || expected[index] != (byte)(highNibble << 4))
                {
                    return false;
                }

                index++;
            }

            return index == expected.Length;
        }

        private static int GetHexNibble(byte value)
        {
            if (value >= '0' && value <= '9')
            {
                return value - '0';
            }

            if (value >= 'A' && value <= 'F')
            {
                return value - 'A' + 10;
            }

            if (value >= 'a' && value <= 'f')
            {
                return value - 'a' + 10;
            }

            return -1;
        }

        public byte[] ReadSignedContent(IInputBytes inputBytes)
        {
            var signedContent = new byte[Length1 + Length2];

            var originalOffset = inputBytes.CurrentOffset;

            try
            {
                inputBytes.Seek(Offset1);
                var read = inputBytes.Read(signedContent.AsSpan(0, Length1));
                if (read != Length1)
                {
                    throw new InvalidOperationException($"Expected to read {Length1} bytes, but read {read} instead.");
                }

                inputBytes.Seek(Offset2);
                read = inputBytes.Read(signedContent.AsSpan(Length1, Length2));
                if (read != Length2)
                {
                    throw new InvalidOperationException($"Expected to read {Length1} bytes, but read {read} instead.");
                }
            }
            finally
            {
                inputBytes.Seek(originalOffset);
            }

            return signedContent;
        }
    }

    private sealed class ParsedPdfSignature
    {
        public PdfSignatureVerificationResult SignatureVerificationResult { get; }

        public SignedCms? Cms { get; }

        public SignerInfo? SignerInfo { get; }

        public byte[]? SignerSignature { get; }

        public DateTimeOffset? SigningTime { get; }

        public string? FieldName { get; }

        /// <summary>
        /// The offset one past the last document byte this signature covers, or <see langword="null"/>
        /// when the byte range could not be established.
        /// </summary>
        public long? CoverageExtent { get; }

        /// <summary>
        /// The encoding of the signature, carried so attached timestamps can report it too.
        /// </summary>
        public PdfSignatureSubFilter SubFilter { get; }

        public ParsedPdfSignature(
            PdfSignatureVerificationResult result,
            SignedCms? cms,
            SignerInfo? signerInfo,
            byte[]? signerSignature,
            DateTimeOffset? signingTime,
            string? fieldName,
            long? coverageExtent = null,
            PdfSignatureSubFilter subFilter = PdfSignatureSubFilter.Unknown)
        {
            SignatureVerificationResult = result;
            Cms = cms;
            SignerInfo = signerInfo;
            SignerSignature = signerSignature;
            SigningTime = signingTime;
            FieldName = fieldName;
            CoverageExtent = coverageExtent;
            SubFilter = subFilter;
        }

        public static ParsedPdfSignature FromResult(PdfSignatureVerificationResult result, long? coverageExtent = null)
        {
            return new ParsedPdfSignature(
                result, null, null, null, result.SigningTime, result.FieldName, coverageExtent, result.SubFilter);
        }

        public ParsedPdfSignature WithResult(PdfSignatureVerificationResult result)
        {
            return new ParsedPdfSignature(
                result, Cms, SignerInfo, SignerSignature, SigningTime, FieldName, CoverageExtent, SubFilter);
        }
    }

    private sealed class TimestampInfo
    {
        public string HashAlgorithmOid { get; }

        public byte[] MessageImprint { get; }

        public DateTimeOffset GenerationTime { get; }

        public TimestampInfo(string hashAlgorithmOid, byte[] messageImprint, DateTimeOffset generationTime)
        {
            HashAlgorithmOid = hashAlgorithmOid;
            MessageImprint = messageImprint;
            GenerationTime = generationTime;
        }
    }
}