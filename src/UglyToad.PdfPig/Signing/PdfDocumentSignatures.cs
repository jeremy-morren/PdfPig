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
    private const string CodeSigningEkuOid = "1.3.6.1.5.5.7.3.3";
    private const string TimeStampingEkuOid = "1.3.6.1.5.5.7.3.8";
    private const string Pkcs7DetachedSubFilter = "adbe.pkcs7.detached";
    private const string SigningTimeOid = "1.2.840.113549.1.9.5";
    private const string SignatureTimestampTokenOid = "1.2.840.113549.1.9.16.2.14";

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
        return result;
    }


    private static ParsedPdfSignature VerifySignatureField(
        AcroSignatureField signatureField,
        AcroSignatureValue signatureValue,
        IInputBytes pdfBytes,
        PdfSignatureVerificationOptions options)
    {
        var fieldName = signatureField.Information.FullyQualifiedName ?? signatureField.Information.PartialName;

        if (!string.Equals(signatureValue.SubFilter, Pkcs7DetachedSubFilter, StringComparison.Ordinal))
        {
            return ParsedPdfSignature.FromResult(CreateInvalidResult(
                PdfSignatureError.UnsupportedSubFilter,
                fieldName,
                $"Unsupported signature subfilter: {signatureValue.SubFilter ?? "<missing>"}."));
        }

        if (!TryGetByteRange(signatureValue, pdfBytes.Length, out var byteRange, out var byteRangeErrorMessage))
        {
            return ParsedPdfSignature.FromResult(CreateInvalidResult(
                byteRangeErrorMessage is null ? PdfSignatureError.ByteRangeMissing : PdfSignatureError.ByteRangeInvalid,
                fieldName,
                byteRangeErrorMessage ?? "The signature dictionary does not contain a /ByteRange entry."));
        }

        var coversEntireDocument = byteRange.CoversEntireDocument(signatureValue.ContentsFieldValueLength, pdfBytes.Length);

        if (!TryGetContentsBytes(signatureValue, out var contentsBytes, out var contentsError))
        {
            return ParsedPdfSignature.FromResult(CreateInvalidResult(
                contentsError ?? PdfSignatureError.ContentsMissing,
                fieldName,
                "The signature dictionary does not contain usable CMS contents.",
                coversEntireDocument: coversEntireDocument));
        }

        var signedContent = byteRange.ReadSignedContent(pdfBytes);

        if (!TryDecodeSignedCms(contentsBytes, signedContent, out var cms, out var cmsBytes))
        {
            return ParsedPdfSignature.FromResult(CreateInvalidResult(
                PdfSignatureError.CmsInvalid,
                fieldName,
                "The CMS payload could not be decoded.",
                coversEntireDocument: coversEntireDocument));
        }

        if (cms.SignerInfos.Count == 0)
        {
            return ParsedPdfSignature.FromResult(CreateInvalidResult(
                PdfSignatureError.SigningCertificateMissing,
                fieldName,
                "The CMS payload did not contain a signer.",
                coversEntireDocument: coversEntireDocument));
        }

        var signerInfo = cms.SignerInfos[0];
        var signingTime = GetSigningTime(signerInfo);

        try
        {
            signerInfo.CheckSignature(true);
        }
        catch (CryptographicException)
        {
            return ParsedPdfSignature.FromResult(CreateInvalidResult(
                PdfSignatureError.SignatureMismatch,
                fieldName,
                "The CMS signature did not validate against the PDF byte ranges.",
                signerInfo.Certificate, signingTime,
                coversEntireDocument: coversEntireDocument));
        }

        var signingCertificate = signerInfo.Certificate;
        if (signingCertificate is null)
        {
            return ParsedPdfSignature.FromResult(CreateInvalidResult(
                PdfSignatureError.SigningCertificateMissing,
                fieldName,
                "The CMS payload did not expose a signing certificate.",
                null, signingTime,
                coversEntireDocument: coversEntireDocument));
        }

        if (!HasEnhancedKeyUsage(signingCertificate, CodeSigningEkuOid))
        {
            return ParsedPdfSignature.FromResult(CreateInvalidResult(
                PdfSignatureError.EKUNotValidForSigning,
                fieldName,
                "The signing certificate does not have a document-signing EKU.",
                signingCertificate, signingTime,
                coversEntireDocument: coversEntireDocument));
        }

        var chainError = ValidateCertificate(signingCertificate,
            cms.Certificates,
            options.SignatureTrust,
            signingTime,
            PdfSignatureError.SigningCertificateNotTrusted,
            PdfSignatureError.SigningCertificateRevoked,
            PdfSignatureError.SigningCertificateExpired);
        if (chainError is not null)
        {
            return ParsedPdfSignature.FromResult(CreateInvalidResult(
                chainError.Value,
                fieldName,
                $"The signing certificate could not be trusted: {chainError.Value}.",
                signingCertificate, signingTime,
                coversEntireDocument: coversEntireDocument));
        }

        if (!TryGetSignerSignature(cmsBytes, out var signerSignature))
        {
            return ParsedPdfSignature.FromResult(CreateInvalidResult(
                PdfSignatureError.CmsInvalid,
                fieldName,
                "The CMS payload did not expose a signer signature value.",
                signingCertificate, signingTime,
                coversEntireDocument: coversEntireDocument));
        }

        return new ParsedPdfSignature(
            CreateValidResult(fieldName, "The signature is valid.", signingCertificate, signingTime, null, coversEntireDocument),
            cms,
            signerInfo,
            signerSignature,
            signingTime,
            fieldName);
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

        if (!HasEnhancedKeyUsage(timestampCertificate, TimeStampingEkuOid))
        {
            return CreateInvalidResult(
                PdfSignatureError.TimeStampCertificateNotTrusted,
                parsedSignature.FieldName,
                "The TSA certificate does not have the timeStamping EKU.",
                timestampCertificate, parsedSignature.SigningTime, timestampInfo.GenerationTime,
                coversEntireDocument);
        }

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

    private static bool HasEnhancedKeyUsage(X509Certificate2 certificate, string requiredOid) =>
        certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(x => x.EnhancedKeyUsages.Cast<Oid>())
            .Any(x => string.Equals(x.Value, requiredOid, StringComparison.Ordinal));

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
        bool coversEntireDocument = false)
    {
        return new PdfSignatureVerificationResult(error, fieldName, message, certificate, signingTime, timestampTime, coversEntireDocument);
    }

    private static PdfSignatureVerificationResult CreateValidResult(string? fieldName, string message, X509Certificate2? certificate, DateTimeOffset? signingTime, DateTimeOffset? timestampTime, bool coversEntireDocument = false)
    {
        return new PdfSignatureVerificationResult(null, fieldName, message, certificate, signingTime, timestampTime, coversEntireDocument);
    }

    private readonly record struct SignatureByteRange(long Offset1, int Length1, long Offset2, int Length2)
    {
        public bool CoversEntireDocument(long signatureFieldLength, long documentLength)
        {
            return Offset1 == 0 &&
                   Length1 + signatureFieldLength == Offset2 &&
                   Offset2 + Length2 == documentLength;
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

        public ParsedPdfSignature(PdfSignatureVerificationResult result, SignedCms? cms, SignerInfo? signerInfo, byte[]? signerSignature, DateTimeOffset? signingTime, string? fieldName)
        {
            SignatureVerificationResult = result;
            Cms = cms;
            SignerInfo = signerInfo;
            SignerSignature = signerSignature;
            SigningTime = signingTime;
            FieldName = fieldName;
        }

        public static ParsedPdfSignature FromResult(PdfSignatureVerificationResult result)
        {
            return new ParsedPdfSignature(result, null, null, null, result.SigningTime, result.FieldName);
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