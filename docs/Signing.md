# Digital Signatures

> **Draft** — this page is intended for the [PdfPig wiki](https://github.com/UglyToad/PdfPig/wiki) once the signing feature ships.

PdfPig can **add digital signatures** to existing PDF documents and **verify signatures** (including RFC 3161 timestamp tokens) embedded in documents it opens.

- Signing is append-only: PdfPig writes a new incremental revision to the end of the file, so all previously signed bytes remain byte-for-byte identical and any existing signatures stay valid.
- PdfPig owns the PDF mechanics (incremental update, signature field, `/ByteRange`, `/Contents` placeholder patching). The cryptography is delegated to your implementation of a single interface, `IPdfSignatureProvider`, so you can sign with a local certificate, an HSM, or a remote signing service.
- Signatures use `/Filter /Adobe.PPKLite` and `/SubFilter /adbe.pkcs7.detached` (a detached CMS/PKCS#7 signature), the format Adobe Acrobat expects.

## Signing a document

Call `PdfSigner.SignAsync` with an open `PdfDocument`, an output stream, and your signature provider:

```csharp
using UglyToad.PdfPig;
using UglyToad.PdfPig.Signing;

using var document = PdfDocument.Open(@"C:\docs\contract.pdf");
using var output = File.Create(@"C:\docs\contract-signed.pdf");

await PdfSigner.SignAsync(
    document,
    output,
    new MySignatureProvider(certificate),
    new PdfSignatureOptions
    {
        FieldName = "ApprovalSignature",
        Metadata = new PdfSignatureMetadata(
            reason: "Approved",
            location: "London",
            contactInfo: "ops@example.com",
            name: "Jane Smith")
    });
```

The output stream receives a full copy of the source document followed by the new signed revision.

### Implementing `IPdfSignatureProvider`

The provider has two responsibilities:

- `SignAsync` — produce a **detached** CMS/PKCS#7 signature over the exact bytes in `PdfSigningRequest.ContentToSign`.
- `TimestampAsync` — optionally post-process the CMS signature, typically to embed an RFC 3161 timestamp token. Return `null` to leave the signature unchanged. It is only called when `PdfSignatureOptions.AddTimestamp` is `true`.

A minimal provider using `System.Security.Cryptography.Pkcs`:

```csharp
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using UglyToad.PdfPig.Signing;

public sealed class MySignatureProvider : IPdfSignatureProvider
{
    private readonly X509Certificate2 certificate;

    public MySignatureProvider(X509Certificate2 certificate)
    {
        this.certificate = certificate;
    }

    public Task<ReadOnlyMemory<byte>> SignAsync(
        PdfSigningRequest request,
        CancellationToken cancellationToken = default)
    {
        var cms = new SignedCms(new ContentInfo(request.ContentToSign), detached: true);

        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
        {
            IncludeOption = X509IncludeOption.WholeChain,
            DigestAlgorithm = new Oid(MapDigest(request.DigestAlgorithm))
        };

        signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));

        cms.ComputeSignature(signer);
        return Task.FromResult<ReadOnlyMemory<byte>>(cms.Encode());
    }

    public Task<ReadOnlyMemory<byte>?> TimestampAsync(
        PdfTimestampRequest request,
        CancellationToken cancellationToken = default)
    {
        // Return null when no timestamping is required.
        // See "Adding a trusted timestamp" below for a full implementation.
        return Task.FromResult<ReadOnlyMemory<byte>?>(null);
    }

    private static string MapDigest(string digestAlgorithm) => digestAlgorithm switch
    {
        "SHA-256" => "2.16.840.1.101.3.4.2.1",
        "SHA-384" => "2.16.840.1.101.3.4.2.2",
        "SHA-512" => "2.16.840.1.101.3.4.2.3",
        _ => throw new NotSupportedException($"Unsupported digest algorithm: {digestAlgorithm}")
    };
}
```

### Signing options

`PdfSignatureOptions` controls the created signature field and dictionary:

| Option | Default | Meaning |
| --- | --- | --- |
| `FieldName` | `"Signature1"` | Name of the new AcroForm signature field. Must not already exist in the document. |
| `ReservedContentsLength` | `16384` | Bytes reserved for the CMS payload. Signing fails if the final CMS object is larger, so leave headroom for certificate chains and timestamp tokens. |
| `Filter` | `"Adobe.PPKLite"` | Signature handler name written to `/Filter`. |
| `SubFilter` | `"adbe.pkcs7.detached"` | Signature encoding written to `/SubFilter`. |
| `DigestAlgorithm` | `"SHA-256"` | Digest requested from the provider (`SHA-256`, `SHA-384` or `SHA-512`). |
| `AddTimestamp` | `false` | When `true`, `TimestampAsync` is invoked with the CMS signature. |
| `Metadata` | empty | Optional `/Reason`, `/Location`, `/ContactInfo` and `/Name` values. |
| `Placement` | invisible | Optional `PdfSignatureFieldPlacement(pageNumber, bounds)` for a visible widget rectangle. When omitted an invisible (zero-area) widget is placed on page 1. No appearance stream is generated. |

### Adding a trusted timestamp (RFC 3161)

The `/M` date in the signature dictionary and the CMS signing-time attribute are both claims made by the signer. A **trusted** timestamp requires an RFC 3161 token issued by a Time Stamp Authority (TSA) and embedded in the CMS signature as the `id-aa-signatureTimeStampToken` unsigned attribute. PdfPig deliberately does not talk to TSAs itself — your provider's `TimestampAsync` does, so you can use any HTTP TSA, an enterprise service, or an in-memory implementation in tests.

Set `AddTimestamp = true` in the options and implement `TimestampAsync`. The example below is a complete provider that signs with a certificate and timestamps via [DigiCert's public timestamp server](http://timestamp.digicert.com) by default:

```csharp
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using UglyToad.PdfPig.Signing;

public sealed class TimestampedSignatureProvider : IPdfSignatureProvider
{
    private static readonly Uri DefaultTimestampServer = new("http://timestamp.digicert.com");

    private readonly X509Certificate2 _certificate;
    private readonly HttpClient _httpClient;
    private readonly Uri _timestampServer;

    public TimestampedSignatureProvider(
        X509Certificate2 certificate,
        Uri? timestampServer = null,
        HttpClient? httpClient = null)
    {
        _certificate = certificate;
        _timestampServer = timestampServer ?? DefaultTimestampServer;
        _httpClient = httpClient ?? new HttpClient();
    }

    public Task<ReadOnlyMemory<byte>> SignAsync(
        PdfSigningRequest request,
        CancellationToken cancellationToken = default)
    {
        var cms = new SignedCms(new ContentInfo(request.ContentToSign), detached: true);

        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, _certificate)
        {
            IncludeOption = X509IncludeOption.WholeChain,
            DigestAlgorithm = new Oid(MapDigestOid(request.DigestAlgorithm))
        };

        signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));

        cms.ComputeSignature(signer);
        return Task.FromResult<ReadOnlyMemory<byte>>(cms.Encode());
    }

    public async Task<ReadOnlyMemory<byte>?> TimestampAsync(
        PdfTimestampRequest request,
        CancellationToken cancellationToken = default)
    {
        // Decode the CMS signature produced by SignAsync.
        var cms = new SignedCms();
        cms.Decode(request.CmsSignature.ToArray());

        var signerInfo = cms.SignerInfos[0];

        // Build an RFC 3161 timestamp request over the signature value.
        var timestampRequest = Rfc3161TimestampRequest.CreateFromSignerInfo(
            signerInfo,
            MapHashAlgorithmName(request.DigestAlgorithm),
            requestSignerCertificates: true);

        // Build the HTTP request body
        var request = new HttpRequestMessage()
        {
            Uri = _timestampServer,
            Method = HttpMethod.Post,
            Content = new ByteArrayContent(timestampRequest.Encode()) 
            {
                Headers = { ContentType =  new MediaTypeHeaderValue("application/timestamp-query") }
            }
        }
        using var response = await _httpClient.SendAsync(request, cancellationToken);
        if (response.IsSuccessStatusCode)
            throw new HttpRequestException(
                "RFC 3161 timestamp server returned error status", null, response.StatusCode);

        var responseBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);

        // Validate the response against our request (nonce, message imprint) and extract the timestamp token.
        var token = timestampRequest.ProcessResponse(responseBytes, out _);

        // Embed the token in the CMS signature as the id-aa-signatureTimeStampToken (1.2.840.113549.1.9.16.2.14) unsigned attribute.
        signerInfo.AddUnsignedAttribute(new AsnEncodedData(
            new Oid("1.2.840.113549.1.9.16.2.14"),
            token.AsSignedCms().Encode()));

        return cms.Encode();
    }

    private static string MapDigestOid(string digestAlgorithm) => digestAlgorithm switch
    {
        "SHA-256" => "2.16.840.1.101.3.4.2.1",
        "SHA-384" => "2.16.840.1.101.3.4.2.2",
        "SHA-512" => "2.16.840.1.101.3.4.2.3",
        _ => throw new NotSupportedException($"Unsupported digest algorithm: {digestAlgorithm}")
    };

    private static HashAlgorithmName MapHashAlgorithmName(string digestAlgorithm) => digestAlgorithm switch
    {
        "SHA-256" => HashAlgorithmName.SHA256,
        "SHA-384" => HashAlgorithmName.SHA384,
        "SHA-512" => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException($"Unsupported digest algorithm: {digestAlgorithm}")
    };
}
```

Usage:

```csharp
await PdfSigner.SignAsync(
    document,
    output,
    new TimestampedSignatureProvider(certificate), // timestamps via DigiCert by default
    new PdfSignatureOptions
    {
        FieldName = "ApprovalSignature",
        AddTimestamp = true
    });
```

Afterwards `document.GetTimestampSignatures()` on the signed output returns one result for the embedded token, with `TimeStampTime` set to the TSA-asserted time.

Notes:

- `Rfc3161TimestampRequest` requires .NET Core 3.0+ / the `System.Security.Cryptography.Pkcs` package; on .NET Framework use a library such as BouncyCastle to build the timestamp request instead.
- The timestamp token (including the TSA's certificate chain) is stored inside the reserved `/Contents` area, so leave enough `ReservedContentsLength` headroom — the default of 16384 bytes is usually sufficient for a signature chain plus one token.
- Other public TSAs (e.g. `http://timestamp.sectigo.com`, `http://rfc3161timestamp.globalsign.com/advanced`) can be passed via the `timestampServer` constructor parameter. Check the TSA's usage policy before using it in production.

### Adding multiple signatures

To add a second signature, open the signed output and sign it again with a different field name. Each call appends a new revision, so earlier signatures remain valid — their `CoversEntireDocument` value will be `false` because later revisions now follow the bytes they signed. This is normal for multiply-signed documents and does not make them invalid, because the later signature covers the appended revision.

```csharp
using var signedOnce = PdfDocument.Open(firstOutputBytes);
await PdfSigner.SignAsync(signedOnce, secondOutput, secondProvider,
    new PdfSignatureOptions { FieldName = "Countersignature" });
```

## Verifying signatures

`PdfDocument.GetSignatures` discovers every applied signature in the document's AcroForm field tree, validates the `/ByteRange` and CMS payload against the file bytes, verifies the signer's certificate chain, and returns one result per signature (or `null` when the document contains no applied signatures):

```csharp
using var document = PdfDocument.Open(@"C:\docs\contract-signed.pdf");

var signatures = document.GetSignatures();

if (signatures is null)
{
    Console.WriteLine("The document is not signed.");
    return;
}

foreach (var signature in signatures)
{
    Console.WriteLine($"{signature.FieldName}: valid={signature.IsValid} " +
        $"error={signature.ValidationError} signer={signature.Certificate?.Subject} " +
        $"coversEntireDocument={signature.CoversEntireDocument}");

    // Or, to fail fast:
    signature.ThrowIfInvalid();
}
```

Each `PdfSignatureVerificationResult` exposes:

- `IsValid` / `ValidationError` — `ValidationError` is `null` when the signature is valid; otherwise a specific `PdfSignatureError` value (for example `SignatureMismatch`, `SigningCertificateNotTrusted`, `SigningCertificateExpired`).
- `CoversEntireDocument` — whether this signature's byte range spans the whole file, excluding only the embedded signature contents. `false` is normal for all but the last signature of a multiply-signed document, since each later signature appends a revision the earlier ones cannot include. You do not need to check it to be safe (see below); it is exposed for diagnostics and for callers who want to know exactly what each signature covers.
- `Certificate`, `SigningTime`, `TimeStampTime`, `FieldName`, `Message` — diagnostic details.

### Content appended after signing

`IsValid` accounts for unsigned trailing content, so checking it alone is safe. If a signature's byte range stops short of the end of the file and no other signature reaches further, the remaining bytes were appended after every signature was applied and nothing vouches for them. That signature is reported as invalid with `PdfSignatureError.DocumentModifiedAfterSigning`, even though its CMS payload verifies correctly. `Certificate` and `SigningTime` are still populated, so you can distinguish "signed, then modified" from "never signed".

A signature superseded by a later one is not affected: in a multiply-signed document the earlier signatures stay valid because a subsequent signature covers the revision they are missing.

```csharp
foreach (var signature in signatures)
{
    if (signature.ValidationError == PdfSignatureError.DocumentModifiedAfterSigning)
    {
        Console.WriteLine(
            $"{signature.FieldName} was applied by {signature.Certificate?.Subject}, " +
            "but the document has been modified since.");
    }
}
```

PdfPig does not implement DocMDP, so it cannot tell whether an incremental update was of a kind the signer permitted (form filling, for example). It therefore treats any trailing content no signature covers as a modification. If your workflow legitimately appends permitted updates, inspect `ValidationError` for this specific value rather than relying on `IsValid` alone.

### Verifying timestamps

`PdfDocument.GetTimestampSignatures` extracts RFC 3161 timestamp tokens embedded in the discovered CMS signatures, verifies each token against the signature value it timestamps, and validates the TSA certificate chain. It returns `null` when no signature carries a timestamp token.

```csharp
var timestamps = document.GetTimestampSignatures();

if (timestamps is not null)
{
    foreach (var timestamp in timestamps)
    {
        timestamp.ThrowIfInvalid();
        Console.WriteLine($"{timestamp.FieldName} timestamped at {timestamp.TimeStampTime}");
    }
}
```

### Trust options

By default both the signer chain and the TSA chain are validated against the operating system certificate store with online revocation checking. Use `PdfSignatureVerificationOptions` to supply your own trust anchors — signer trust and timestamp trust are configured independently:

```csharp
var results = document.GetSignatures(new PdfSignatureVerificationOptions
{
    SignatureTrust = new PdfCertificateTrustOptions
    {
        UseSystemStore = false,
        AdditionalTrustedRoots = [myCompanyRootCertificate],
        AdditionalIntermediateCertificates = [myIssuingCaCertificate],
        RevocationMode = X509RevocationMode.NoCheck
    },
    TimeStampTrust = PdfCertificateTrustOptions.System
});
```

`PdfCertificateTrustOptions` supports three trust models:

- **System store** (`PdfCertificateTrustOptions.System`) — chains must build to a root trusted by the machine.
- **Manual** — `UseSystemStore = false` with explicit `AdditionalTrustedRoots` (and optionally intermediates).
- **Hybrid** — `UseSystemStore = true` plus additional manual roots.

`RevocationMode`, `RevocationFlag` and `VerificationFlags` map directly onto .NET's `X509Chain` policy.

### Verification requirements

A signature only verifies as valid when all of the following hold:

1. `/SubFilter` is one PdfPig verifies — see [Signature encodings](#signature-encodings).
2. `/ByteRange` is present, well-formed, and within the file bounds.
3. The span excluded by `/ByteRange` is exactly the `/Contents` value as it appears in the file, delimiters included. A gap of the right size in the wrong place is rejected as `ByteRangeInvalid`, so unsigned content cannot hide in the excluded region.
4. The CMS payload decodes and the detached signature verifies over the signed byte ranges.
5. The signing certificate is present, and where the signature commits to it through an ESS signing-certificate attribute, that commitment matches.
6. The `SignatureCertificateValidator` accepts the certificate (see [Certificate rules](#certificate-rules)).
7. The signer's certificate chain builds to a trusted root under `SignatureTrust`, is not revoked, and is time-valid.

### Signature encodings

`PdfSignatureVerificationResult.SubFilter` reports what was found, whether or not it could be verified.

| `/SubFilter` | `PdfSignatureSubFilter` | Verified |
| --- | --- | --- |
| `adbe.pkcs7.detached` | `Pkcs7Detached` | Yes |
| `ETSI.CAdES.detached` | `CAdESDetached` | Yes |
| `adbe.pkcs7.sha1` | `Pkcs7Sha1` | No — legacy, SHA-1 |
| `adbe.x509.rsa_sha1` | `X509RsaSha1` | No — obsolete, not a CMS payload |
| `ETSI.RFC3161` | `DocumentTimeStamp` | No — a document timestamp rather than a signature |
| anything else, or absent | `Unknown` | No |

The two verified encodings both carry a detached CMS signature over the byte ranges and are checked the same way. They differ in one respect: `ETSI.CAdES.detached` (PAdES) **requires** the signed attributes to commit to the signing certificate through an ESS `signingCertificate` or `signingCertificateV2` attribute, which stops a signature being re-presented with a different certificate carrying the same key. PdfPig verifies that attribute wherever it appears and rejects a CAdES signature that lacks it.

An unverified encoding is reported as `UnsupportedSubFilter` with `SubFilter` naming what it was.

### Certificate rules

Chain building answers "does this certificate come from someone I trust". Deciding whether a certificate was *issued for signing documents* is a separate question, and one PdfPig cannot answer for everybody, so it is delegated to an `ICertificateValidator`:

```csharp
public interface ICertificateValidator
{
    void ValidateCertificate(X509Certificate2 certificate, PdfSignatureSubFilter subFilter);
}
```

Return normally to accept; throw `PdfCertificateValidationFailedException` to reject. A rejected signature is reported with `PdfSignatureError.CertificateValidationFailed`, and the exception you threw is carried on `PdfSignatureVerificationResult.CertificateValidationException`, so your message reaches the caller.

`PdfSignatureVerificationOptions` has one for each role:

| Property | Default |
| --- | --- |
| `SignatureCertificateValidator` | `DocumentSigningEKUValidator` |
| `TimeStampCertificateValidator` | `TimeStampingEKUValidator` |

`DocumentSigningEKUValidator` accepts `id-kp-documentSigning` (RFC 9336), Adobe's `1.2.840.113583.1.1.5`, `emailProtection`, `codeSigning` or `anyExtendedKeyUsage`. There is no single identifier the ecosystem settled on: RFC 9336 defines one, Adobe minted its own, and certificates issued under the Adobe Approved Trust List and Certified Document Services conventionally carry `emailProtection` — the U.S. Government Publishing Office signs with such a certificate.

Set a property to `null` to apply no rules beyond chain building:

```csharp
var options = new PdfSignatureVerificationOptions
{
    SignatureCertificateValidator = null
};
```

Or require something narrower with `EnhancedKeyUsageValidator`:

```csharp
var options = new PdfSignatureVerificationOptions
{
    SignatureCertificateValidator = new EnhancedKeyUsageValidator(new Oid("1.3.6.1.5.5.7.3.36"))
};
```

Write your own for anything else. European **qualified** certificates, for instance, commonly declare no extended key usage at all and convey their purpose through the QCStatements extension instead, so the default validator rejects them:

```csharp
public sealed class QualifiedSignatureValidator : ICertificateValidator
{
    // id-etsi-qct-esign: a qualified certificate for electronic signatures.
    private const string QcTypeESign = "0.4.0.1862.1.6.1";

    public void ValidateCertificate(X509Certificate2 certificate, PdfSignatureSubFilter subFilter)
    {
        if (!DeclaresQcType(certificate, QcTypeESign))
        {
            throw new PdfCertificateValidationFailedException(
                $"'{certificate.Subject}' is not a qualified certificate for electronic signatures.");
        }
    }

    private static bool DeclaresQcType(X509Certificate2 certificate, string qcType) => /* parse 1.3.6.1.5.5.7.1.3 */;
}
```

Note that accepting such a certificate is not the same as validating a *qualified electronic signature* under eIDAS, which additionally requires checking the issuer against the EU Trusted Lists at the time of signing. PdfPig does not do that.

The `subFilter` argument tells the validator which kind of signature the certificate came from, so rules can differ between, say, a legacy Adobe signature and a PAdES one. When a timestamp authority's certificate is checked, it is the subfilter of the signature the timestamp is attached to.

### When certificates are checked for validity

The signing time in the signature dictionary (`/M`) and the CMS signing-time attribute are both claims made by the signer, so PdfPig does not let them decide when the certificate chain is validated — otherwise anyone holding an expired or revoked certificate could backdate a signature and have it verify as trusted.

The signer's chain is validated **as of now**, with one exception: if the signature carries an RFC 3161 timestamp that both commits to that signature and builds to an authority trusted under `TimeStampTrust`, the token's generation time is used instead. That is an assertion the signer cannot forge.

A timestamp authority's own certificate is validated as of the moment it issued the token, since a timestamp is expected to outlive it. Detecting a timestamp forged with a compromised historical authority key would need long-term validation material, which PdfPig does not yet capture.

The practical consequence is that **a signature whose certificate has since expired is reported as `SigningCertificateExpired` unless it carries a trusted timestamp.** This is the correct answer without long-term validation material, which PdfPig does not yet support, but it means old documents may not verify even though they were validly signed at the time. Timestamp your signatures if they need to outlive the signing certificate.

## Reading signature fields without verifying

Signature fields are also exposed through the AcroForm API. `AcroSignatureField.SignatureValue` gives read-only access to the parsed signature dictionary (`Filter`, `SubFilter`, `ByteRange`, raw CMS `Contents`, `Metadata`, `ModifiedDate`) without performing any cryptographic validation:

```csharp
if (document.TryGetForm(out var form))
{
    foreach (var field in form.GetFields().OfType<AcroSignatureField>())
    {
        if (field.IsSigned)
        {
            Console.WriteLine($"{field.Information.FullyQualifiedName}: {field.SignatureValue!.SubFilter}");
        }
    }
}
```

## Current limitations

- **Encrypted documents are not supported** for signing — `SignAsync` throws `NotSupportedException`.
- Signing produces `adbe.pkcs7.detached` only. Verification also accepts `ETSI.CAdES.detached`; the remaining subfilters report `UnsupportedSubFilter`.
- No long-term validation material is read or written. The `/DSS` dictionary holding archived certificates, CRLs and OCSP responses is ignored, so a signature whose certificate has expired needs an embedded trusted timestamp to still verify.
- Qualified certificates are not validated against the EU Trusted Lists, so PdfPig cannot tell you a signature is *qualified* under eIDAS.
- The incremental update is written with a classic cross-reference **table**. Signing documents that use cross-reference streams may produce files some strict readers reject.
- No certification (DocMDP) signatures, field locking, or modification-detection policies.
- No long-term validation material (DSS/VRI, embedded CRLs/OCSP) and no `DocTimeStamp` revisions — timestamps are embedded in the CMS signature only.
- No generated visible appearance stream; a visible placement reserves the rectangle only.
- Signing always creates a new field — signing into an existing empty signature field is not supported.
- One signature per `SignAsync` call.
