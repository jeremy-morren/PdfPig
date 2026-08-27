# PDF Signing Draft

This note describes the minimum work required to add PDF signing to PdfPig while keeping the consumer-facing integration small. The target is:

- PdfPig owns the PDF syntax, incremental update, field creation, `/ByteRange`, and `/Contents` handling.
- The consumer only implements one interface, with one hook to create the CMS signature and one hook to optionally timestamp that CMS signature.

## Why this needs a new write path

PdfPig already has some of the read-side pieces needed for signing:

- Signature fields are parsed via `AcroSignatureField` and `SignatureFlags`.
- The parser understands incremental update chains through trailer `/Prev` entries.

The missing piece is write support for append-only incremental updates. The current writer stack (`PdfDocumentBuilder`, `PdfStreamWriter`, `TokenWriter`) creates new documents from scratch and finishes them with a new cross-reference table. A valid digital signature cannot be produced by rewriting the whole file because the signed byte ranges must remain byte-for-byte stable.

## What PDF signing actually is

PDF signing is not just "sign some bytes". It is two separate operations that must line up exactly.

### 1. The PDF operation

PdfPig must:

- create a new incremental revision of the file
- add or update a signature field
- create a signature dictionary
- reserve fixed-width placeholders for `/ByteRange` and `/Contents`
- write the updated xref and trailer with `/Prev`

At the PDF level, Acrobat expects a signature dictionary whose `/Contents` contains a DER-encoded CMS object as a hex string and whose `/ByteRange` names the exact file bytes that were hashed.

### 2. The cryptographic operation

The signer implementation must:

- hash the exact byte ranges identified by `/ByteRange`
- produce a detached CMS/PKCS#7 signature over those bytes
- optionally add an RFC 3161 timestamp token to that CMS signature

For the first implementation, the practical Acrobat-compatible target is:

- `/Filter /Adobe.PPKLite`
- `/SubFilter /adbe.pkcs7.detached` by default
- a detached CMS `SignedData` object in `/Contents`

That means PDF signing in PdfPig is really:

1. build the exact PDF revision that will be signed
2. ask the user implementation for a CMS object over that revision's byte ranges
3. embed the CMS bytes into `/Contents` without changing any already-measured offsets

## What timestamping means in this design

There are three different "times" that people often conflate:

- the PDF `/M` value in the signature dictionary
- the local signing time recorded as a CMS attribute
- a trusted RFC 3161 timestamp token issued by a Time Stamp Authority (TSA)

Only the third one is a trusted timestamp.

For this design, timestamping means:

- PdfPig first asks the provider to create the detached CMS signature
- PdfPig then optionally asks the same provider interface to return a timestamped version of that CMS signature

In other words, phase 2 timestamping here means embedding an RFC 3161 timestamp token into the CMS signature returned by the provider. It does not mean introducing a separate PDF `DocTimeStamp` revision yet.

The timestamp token is not fetched by PdfPig. That is intentional. The provider implementation can:

- call a real TSA over HTTP
- call an in-memory TSA used in tests
- call an HSM-backed or enterprise-specific service

PdfPig only sees CMS bytes in and CMS bytes out.

This keeps "timestamp server" behavior out of PdfPig while still making timestamping easy to plug in.

## Proposed public API

The consumer-facing contract should be a dedicated signing entry point plus one interface.

```csharp
public interface IPdfSignatureProvider
{
    ValueTask<ReadOnlyMemory<byte>> SignAsync(PdfSigningRequest request, CancellationToken cancellationToken = default);

    ValueTask<ReadOnlyMemory<byte>> TimestampAsync(PdfTimestampRequest request, CancellationToken cancellationToken = default);
}

public sealed class PdfSigningRequest
{
    public Stream ContentToSign { get; }
    public string DigestAlgorithm { get; }
    public string Filter { get; }
    public string SubFilter { get; }
    public PdfSignatureMetadata Metadata { get; }
    public int ReservedContentsLength { get; }
}

public sealed class PdfTimestampRequest
{
    public ReadOnlyMemory<byte> CmsSignature { get; }
    public string DigestAlgorithm { get; }
    public string Filter { get; }
    public string SubFilter { get; }
    public PdfSignatureMetadata Metadata { get; }
}

public sealed class PdfSignatureOptions
{
    public string FieldName { get; set; } = "Signature1";
    public int ReservedContentsLength { get; set; } = 16384;
    public string Filter { get; set; } = "Adobe.PPKLite";
    public string SubFilter { get; set; } = "adbe.pkcs7.detached";
    public string DigestAlgorithm { get; set; } = "SHA-256";
    public bool AddTimestamp { get; set; }
    public PdfSignatureMetadata Metadata { get; set; } = PdfSignatureMetadata.Empty;
    public PdfSignatureFieldPlacement? Placement { get; set; }
}

public static class PdfSigner
{
    public static ValueTask SignAsync(
        PdfDocument document,
        Stream output,
        IPdfSignatureProvider signatureProvider,
        PdfSignatureOptions? options = null,
        CancellationToken cancellationToken = default);
}
```

This keeps the consumer responsibility narrow:

- `SignAsync(...)` reads `request.ContentToSign` and returns a detached CMS/PKCS#7 signature
- `TimestampAsync(...)` receives that CMS signature and returns an updated CMS signature containing a trusted timestamp token when requested

Everything else stays inside PdfPig.

PdfPig should not define a separate `ITimestampServer` abstraction. The timestamp transport and protocol integration remain user code behind `TimestampAsync(...)`.

## Proposed verification API

Verification should be read-side API on `PdfDocument`, not a separate static helper. Signing needs raw input and append-writing, so `PdfSigner` still makes sense there. Verification is the opposite: the caller already has a parsed document and wants PdfPig to inspect its signature fields, CMS payloads, byte ranges, signer certificates, and timestamp tokens.

The top-level shape could look like this:

```csharp
public sealed class PdfSignatureVerificationOptions
{
    public PdfCertificateTrustOptions SignatureTrust { get; set; } = PdfCertificateTrustOptions.System;
    public PdfCertificateTrustOptions TimeStampTrust { get; set; } = PdfCertificateTrustOptions.System;
}

public sealed class PdfCertificateTrustOptions
{
    public static PdfCertificateTrustOptions System { get; } = new PdfCertificateTrustOptions
    {
        UseSystemStore = true
    };

    public bool UseSystemStore { get; init; }
    public IReadOnlyList<X509Certificate2> AdditionalTrustedRoots { get; init; } = Array.Empty<X509Certificate2>();
    public IReadOnlyList<X509Certificate2> AdditionalIntermediateCertificates { get; init; } = Array.Empty<X509Certificate2>();
    public X509RevocationMode RevocationMode { get; init; } = X509RevocationMode.Online;
    public X509RevocationFlag RevocationFlag { get; init; } = X509RevocationFlag.ExcludeRoot;
    public X509VerificationFlags VerificationFlags { get; init; } = X509VerificationFlags.NoFlag;
}

public enum PdfSignatureError
{
    SignatureDictionaryMissing,
    UnsupportedSubFilter,
    ByteRangeMissing,
    ByteRangeInvalid,
    ContentsMissing,
    ContentsInvalid,
    CmsInvalid,
    SignatureMismatch,
    SigningCertificateMissing,
    SigningCertificateNotTrusted,
    SigningCertificateRevoked,
    SigningCertificateExpired,
    TimeStampTokenInvalid,
    TimeStampTokenMismatch,
    TimeStampCertificateMissing,
    TimeStampCertificateNotTrusted,
    TimeStampCertificateRevoked,
    TimeStampCertificateExpired,
    TimeStampBeforeSigning,
    Unknown
}

public sealed class PdfSignatureResult
{
    public bool IsValid => ValidationError is null;
    public PdfSignatureError? ValidationError { get; }
    public string? FieldName { get; }
    public string? Message { get; }
    public X509Certificate2? Certificate { get; }
    public DateTimeOffset? SigningTime { get; }
    public DateTimeOffset? TimeStampTime { get; }

    public void ThrowIfInvalid();
}

public partial class PdfDocument
{
    public List<PdfSignatureResult>? GetSignatures(
        PdfSignatureVerificationOptions? options = null);

    public List<PdfSignatureResult>? GetTimestampSignatures(
        PdfSignatureVerificationOptions? options = null);
}
```

This keeps the common path simple:

- call `document.GetSignatures()`
- inspect `results?[0].IsValid`
- or iterate and call `ThrowIfInvalid()` on each returned item

`GetSignatures()` should return `null` if no matching PDF signatures exist in scope, not an empty list. `GetTimestampSignatures()` should return `null` if no matching timestamp tokens exist in scope, not an empty list.

Signature discovery should work the same way Acrobat does:

- start from the document catalog's `/AcroForm`
- walk the field tree under `/AcroForm.Fields`
- resolve inherited field properties from parent fields
- select terminal fields whose effective `/FT` is `/Sig`
- treat a `/V` entry on that field as the applied signature value

Each returned `PdfSignatureResult` should expose the effective field name through `FieldName`, meaning the fully resolved AcroForm field name for the signature field that was discovered. If a signature field is unnamed, `FieldName` may still be `null`.

Both methods should return results for all discovered signatures in a documented, stable order. The simplest choice is AcroForm field-tree order.

## Potential better method names

The names you suggested are workable, but there are slightly clearer alternatives.

Preferred pair:

- `GetDocumentSignatures()` for the PDF signatures themselves
- `GetSignatureTimeStamps()` for the RFC 3161 tokens attached to those signatures

Other reasonable options:

- `GetSignatures()` and `GetSignatureTimeStamps()`
- `GetEmbeddedSignatures()` and `GetEmbeddedTimeStamps()`

`GetTimestampSignatures()` is understandable, but it reads more like "PDF signatures whose purpose is timestamping" than "timestamps attached to signatures". `GetSignatureTimeStamps()` is more explicit about what is being returned.

## Verification trust model

The important design point is to keep signer trust and timestamp trust separate. They often use different trust anchors.

- `SignatureTrust` validates the certificate chain for the certificate that created the CMS signature
- `TimeStampTrust` validates the TSA certificate chain for the RFC 3161 token if one is present

Each trust configuration supports the scenarios you listed:

- system store only: `UseSystemStore = true`, no extra certificates
- manual store only: `UseSystemStore = false`, populate `AdditionalTrustedRoots` and optionally `AdditionalIntermediateCertificates`
- hybrid trust: `UseSystemStore = true` plus additional manual roots/intermediates

That maps cleanly to .NET chain-building behavior. PdfPig can build an `X509Chain` separately for the signer and for the TSA token signer, using the system trust store, a caller-supplied trust store, or both.

## Verification behavior

At a high level `PdfDocument.GetSignatures(...)` would:

1. Walk the AcroForm field tree, resolve inherited properties, and locate every terminal field whose effective `/FT` is `/Sig`.
2. If no matching signatures exist, return `null`.
3. For each field with a `/V` entry, validate `/ByteRange`, `/Contents`, and the signed byte spans against the document bytes.
4. Decode each CMS payload and verify the detached CMS signature.
5. Build and validate each signer certificate chain using `SignatureTrust`.
6. Return one `PdfSignatureResult` per discovered signature, with the resolved field name in `FieldName`, `ValidationError = null` when valid, and a specific error when invalid.

At a high level `PdfDocument.GetTimestampSignatures(...)` would:

1. Start from the signatures discovered by `GetSignatures(...)`.
2. If no matching signatures exist, return `null`.
3. Extract embedded RFC 3161 timestamp tokens from the CMS signatures.
4. If none of the selected signatures contain a timestamp token, return `null`.
5. For each timestamp token, verify that it is correctly bound to the selected CMS signer info.
6. Build and validate each TSA certificate chain using `TimeStampTrust`.
7. Return one `PdfSignatureResult` per discovered timestamp token, carrying the same source signature field name in `FieldName`, with `ValidationError = null` when valid and a specific error when invalid.

## Draft `PdfSignatureError` members

The enum should cover actual validation failures only. Absence is represented by `null`, not by an enum member.

- `SignatureDictionaryMissing`: the field exists but does not contain a usable signature dictionary
- `UnsupportedSubFilter`: the signature uses a subfilter PdfPig does not verify
- `ByteRangeMissing`: `/ByteRange` is absent
- `ByteRangeInvalid`: `/ByteRange` is malformed or out of bounds
- `ContentsMissing`: `/Contents` is absent
- `ContentsInvalid`: `/Contents` is malformed, truncated, or not valid hex/DER payload data
- `CmsInvalid`: the CMS object cannot be decoded or is structurally invalid
- `SignatureMismatch`: the detached CMS signature does not validate against the signed byte ranges
- `SigningCertificateMissing`: no signer certificate can be resolved from the CMS payload
- `SigningCertificateNotTrusted`: the signer chain does not build to a trusted root under `SignatureTrust`
- `SigningCertificateRevoked`: the signer certificate or one of its issuers is revoked
- `SigningCertificateExpired`: the signer certificate chain is outside its validity window for the validation moment
- `TimeStampTokenInvalid`: the RFC 3161 token cannot be decoded or is structurally invalid
- `TimeStampTokenMismatch`: the RFC 3161 token does not match the selected CMS signer info
- `TimeStampCertificateMissing`: no TSA signing certificate can be resolved from the timestamp token
- `TimeStampCertificateNotTrusted`: the TSA chain does not build to a trusted root under `TimeStampTrust`
- `TimeStampCertificateRevoked`: the TSA certificate or one of its issuers is revoked
- `TimeStampCertificateExpired`: the TSA certificate chain is outside its validity window for the validation moment
- `TimeStampBeforeSigning`: the timestamp time is inconsistent with the CMS signing time or signed attributes
- `Unknown`: a catch-all for unexpected verification failures that do not map cleanly to a more specific member

## Why the result should not be just an enum

The enum is the right error vocabulary, but the result should still carry a small amount of context.

The practical shape is:

- `IsValid` for the common branch
- nullable `ValidationError` for machine-readable failure handling, where `null` means valid
- optional `FieldName`, `Message`, `Certificate`, `SigningTime`, and `TimeStampTime` for diagnostics
- `ThrowIfInvalid()` for the simple guard case

That gives both styles of usage:

```csharp
var results = document.GetSignatures(new PdfSignatureVerificationOptions
{
    SignatureTrust = new PdfCertificateTrustOptions
    {
        UseSystemStore = false,
        AdditionalTrustedRoots = new[] { mySignerRoot }
    }
});

if (results is not null)
{
    foreach (var result in results)
    {
        result.ThrowIfInvalid();
    }
}
```

and:

```csharp
var signatures = document.GetSignatures(new PdfSignatureVerificationOptions
{
    SignatureTrust = PdfCertificateTrustOptions.System
});

if (signatures is not null)
{
    foreach (var signature in signatures)
    {
        signature.ThrowIfInvalid();
    }
}

var timeStamps = document.GetTimestampSignatures(new PdfSignatureVerificationOptions
{
    TimeStampTrust = PdfCertificateTrustOptions.System
});

if (timeStamps is not null)
{
    foreach (var timeStamp in timeStamps)
    {
        timeStamp.ThrowIfInvalid();
    }
}
```

## Suggested exception model for `ThrowIfInvalid()`

`ThrowIfInvalid()` should throw a focused exception that includes the error and field name.

```csharp
public sealed class PdfSignatureValidationException : Exception
{
    public PdfSignatureError ValidationError { get; }
    public string? FieldName { get; }
}
```

That keeps the API ergonomic without forcing exception-based control flow on every caller.

## Expected signing flow

At a high level `PdfSigner.SignAsync(...)` would:

1. Read the source PDF from `input` and copy its original bytes to the destination stream unchanged.
2. Parse the source cross-reference state to find the latest trailer, root reference, info reference, highest object number, and existing AcroForm if any.
3. Append new or updated objects only.
4. Reserve fixed-width placeholders for `/ByteRange` and `/Contents` in the signature dictionary.
5. Write the incremental xref section and trailer with `/Prev` pointing at the prior revision.
6. Compute the real byte ranges around the `/Contents` placeholder.
7. Expose a stream over those exact byte ranges as `PdfSigningRequest.ContentToSign`.
8. Call `IPdfSignatureProvider.SignAsync(...)` and receive detached CMS bytes.
9. If `PdfSignatureOptions.AddTimestamp` is true, call `IPdfSignatureProvider.TimestampAsync(...)` and receive updated CMS bytes.
10. Hex-encode the final CMS bytes into the reserved `/Contents` area and patch the final `/ByteRange` values without changing file length.
11. Fail if the final CMS value exceeds `ReservedContentsLength`.

## Required internal work

### 1. Append-only writer

Add a writer dedicated to incremental updates instead of extending `PdfDocumentBuilder`.

Required behavior:

- start from an existing file stream instead of emitting `%PDF-` from byte 0
- continue object numbering from the source document's max object number
- track appended object offsets only for the new revision
- write a trailer/xref section with `/Prev`
- preserve all original bytes exactly

This is the core requirement. Without it, the rest of the signing API is not credible.

### 2. Source document inspection helpers

The signing path needs a compact internal model for:

- latest xref offset
- trailer size
- catalog reference
- info reference if present
- AcroForm reference if present
- page references if a visible signature widget is created
- maximum object number across all revisions

Some of this data is already available through the parser, but not in a single writer-friendly abstraction.

### 3. Signature dictionary and field builders

Add internal builders for:

- signature dictionary with `/Type /Sig`, `/Filter`, `/SubFilter`, `/M`, `/Reason`, `/Location`, `/ContactInfo`, `/ByteRange`, `/Contents`
- signature form field (`/FT /Sig`)
- widget annotation if the signature is visible
- AcroForm updates to include the new field and set `SignatureFlags`

For the first version, keep this logic internal and narrowly scoped to signatures. Reusing the general document builder is likely to leak too much non-signing behavior into the append path.

### 4. Fixed-width placeholder patching

Signing requires writing placeholder values first and patching them later without shifting any later byte positions.

That means PdfPig needs an internal utility that can:

- reserve exact byte spans for `/ByteRange` and `/Contents`
- remember their offsets in the output stream
- overwrite them in place after the signature bytes are available
- validate that replacement text fits the reserved width exactly

This patching step is specific enough that it should be modeled explicitly rather than hidden in ad hoc stream seeks.

### 5. Byte-range stream

The signer interface should not receive the whole file including the placeholder gap. It should receive a stream that concatenates:

- bytes from file start to the beginning of `/Contents`
- bytes after `/Contents` to the end of the incremental update

That stream can be implemented as a lightweight wrapper over the destination stream or over two read-only ranges.

### 6. AcroForm creation/update rules

There are two practical scenarios:

- the document already contains an empty signature field
- the document has no signature field and PdfPig creates one

For MVP, supporting both is feasible if the visible appearance story is kept small:

- invisible signature: create a field and widget with a zero rectangle or omit page placement where allowed
- visible signature: allow explicit page number and bounds only, with no generated appearance stream in v1

If appearance generation is required for interoperability with target viewers, it should be a separate phase.

### 7. Cross-reference compatibility decision

One design choice needs to be made up front:

- support incremental updates only for table-based xref output in v1
- or also emit xref streams for newer files

Table-only output is the smaller implementation. Supporting xref streams widens compatibility, especially for files that already rely on newer object storage features. The draft implementation should call this out as an explicit scope decision instead of leaving it ambiguous.

### 8. Error model

Add focused exceptions for cases such as:

- encrypted input not supported for signing
- source document structure cannot be updated incrementally
- returned signature does not fit reserved contents length
- field name collision when auto-creating a signature field
- unsupported xref mode for the current implementation

## Recommended scope for a first implementation

The smallest useful version is:

- detached CMS signature only
- append-only signing of an existing document
- no encryption support
- optional RFC 3161 timestamp token embedded into the returned CMS signature
- no DSS/LTV material
- no certification signatures or field locking rules
- invisible signature, or visible signature with caller-supplied page and rectangle only
- one signature added per call

This is already enough for the common case where the caller has a certificate and wants Acrobat-compatible detached signatures.

## Suggested phased plan

### Phase 1: incremental append infrastructure

- add append-only stream writer
- add placeholder patching utility
- expose internal source-document signing context
- write xref trailer with `/Prev`

### Phase 2: detached signature embedding

- add `PdfSigner`
- add `IPdfSignatureProvider`
- add signature dictionary builder
- support signing into an existing empty field or a new invisible field
- support optional RFC 3161 timestamp token embedding by calling `TimestampAsync(...)`

### Phase 3: visible field support

- create widget annotations on a chosen page
- update page annotation arrays
- optionally add appearance support if interoperability requires it

### Phase 4: advanced validation features

- certification signatures and transform params
- DSS/VRI/LTV support
- multiple signatures across successive revisions

## Test plan

At minimum, add tests for:

- signing an unsigned document with no AcroForm
- signing a document with an existing empty signature field
- signing a document twice in successive revisions
- signing with an in-memory TSA implementation and no network access
- reserved contents too small produces a clear error
- original bytes remain unchanged before the incremental update boundary
- `/ByteRange` values match the real file layout
- produced file validates in Acrobat and a second validator such as `pdfsig`

Compatibility tests should include both xref-table and xref-stream source files once the scope decision is made.

## Provider model

The provider contract should be understood like this:

- `SignAsync(...)` is the required cryptographic step
- `TimestampAsync(...)` is an optional post-processing step over the CMS returned by `SignAsync(...)`

That split matters because it keeps PdfPig independent from TSA transport details. A provider can timestamp by:

- sending an RFC 3161 request over HTTP
- using a local testing helper that behaves like a TSA in memory
- routing through custom enterprise code

PdfPig should never know which of those happened.

## Example consumer usage

```csharp
await PdfSigner.SignAsync(
    input,
    output,
    new PfxFilePdfSignatureProvider(
        pfxPath: @"C:\certs\signer.pfx",
        password: "secret",
        timeStampAuthority: new HttpRfc3161TimeStampAuthority(new Uri("https://tsa.example.com"))),
    new PdfSignatureOptions
    {
        FieldName = "ApprovalSignature",
        AddTimestamp = true,
        Metadata = new PdfSignatureMetadata(
            reason: "Approved",
            location: "London",
            contactInfo: "ops@example.com")
    },
    cancellationToken);
```

Expanded for clarity:

```csharp
await PdfSigner.SignAsync(
    input,
    output,
    new PfxFilePdfSignatureProvider(
        pfxPath: @"C:\certs\signer.pfx",
        password: "secret",
        timeStampAuthority: new HttpRfc3161TimeStampAuthority(new Uri("https://tsa.example.com"))),
    new PdfSignatureOptions
    {
        FieldName = "ApprovalSignature",
        AddTimestamp = true
    },
    cancellationToken);
```

## Sample provider using an RSA `.pfx`

The following sample is illustrative. It shows the intended user experience, not a PdfPig-owned timestamp abstraction.

```csharp
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

public sealed class PfxFilePdfSignatureProvider : IPdfSignatureProvider
{
    private readonly X509Certificate2 certificate;
    private readonly IUserTimeStampAuthority? timeStampAuthority;

    public PfxFilePdfSignatureProvider(
        string pfxPath,
        string password,
        IUserTimeStampAuthority? timeStampAuthority = null)
    {
        certificate = new X509Certificate2(
            pfxPath,
            password,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

        if (certificate.GetRSAPrivateKey() is null)
        {
            throw new InvalidOperationException("The provided PFX does not contain an RSA private key.");
        }

        this.timeStampAuthority = timeStampAuthority;
    }

    public async ValueTask<ReadOnlyMemory<byte>> SignAsync(
        PdfSigningRequest request,
        CancellationToken cancellationToken = default)
    {
        using var content = new MemoryStream();
        await request.ContentToSign.CopyToAsync(content, cancellationToken).ConfigureAwait(false);

        var cms = new SignedCms(
            new ContentInfo(content.ToArray()),
            detached: true);

        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
        {
            IncludeOption = X509IncludeOption.EndCertOnly,
            DigestAlgorithm = new Oid(MapDigestAlgorithm(request.DigestAlgorithm))
        };

        signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));

        cms.ComputeSignature(signer);
        return cms.Encode();
    }

    public ValueTask<ReadOnlyMemory<byte>> TimestampAsync(
        PdfTimestampRequest request,
        CancellationToken cancellationToken = default)
    {
        if (timeStampAuthority is null)
        {
            return ValueTask.FromResult(request.CmsSignature);
        }

        return timeStampAuthority.TimestampCmsAsync(request, cancellationToken);
    }

    private static string MapDigestAlgorithm(string digestAlgorithm) =>
        digestAlgorithm.ToUpperInvariant() switch
        {
            "SHA-256" => "2.16.840.1.101.3.4.2.1",
            "SHA-384" => "2.16.840.1.101.3.4.2.2",
            "SHA-512" => "2.16.840.1.101.3.4.2.3",
            _ => throw new NotSupportedException($"Unsupported digest algorithm: {digestAlgorithm}")
        };
}
```

## User-side timestamp authority abstraction

This interface is not something PdfPig should own. It is just a sample of how a consumer can keep HTTP and in-memory TSA implementations interchangeable.

```csharp
public interface IUserTimeStampAuthority
{
    ValueTask<ReadOnlyMemory<byte>> TimestampCmsAsync(
        PdfTimestampRequest request,
        CancellationToken cancellationToken = default);
}
```

## Sample HTTP TSA implementation

```csharp
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

public sealed class HttpRfc3161TimeStampAuthority : IUserTimeStampAuthority
{
    private readonly Uri url;
    private readonly HttpClient httpClient;

    public HttpRfc3161TimeStampAuthority(Uri url, HttpClient? httpClient = null)
    {
        this.url = url;
        this.httpClient = httpClient ?? new HttpClient();
    }

    public async ValueTask<ReadOnlyMemory<byte>> TimestampCmsAsync(
        PdfTimestampRequest request,
        CancellationToken cancellationToken = default)
    {
        var cms = new SignedCms();
        cms.Decode(request.CmsSignature.ToArray());

        var signerInfo = cms.SignerInfos[0];
        var timeStampRequest = Rfc3161TimestampRequest.CreateFromSignerInfo(
            signerInfo,
            new HashAlgorithmName(request.DigestAlgorithm.Replace("-", string.Empty)),
            requestedPolicyId: null,
            nonce: null,
            requestSignerCertificates: true,
            extensions: null);

        using var content = new ByteArrayContent(timeStampRequest.Encode());
        content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");

        using var response = await httpClient.PostAsync(url, content, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var responseBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        var token = timeStampRequest.ProcessResponse(responseBytes, out _);

        return CmsTimestampUtility.AddSignatureTimeStampToken(
            request.CmsSignature,
            token.AsSignedCms().Encode());
    }
}
```

`CmsTimestampUtility` above is deliberately user code. PdfPig should not own CMS timestamp attribute manipulation.

## Sample in-memory TSA implementation for tests

The same provider can be tested without any web request:

```csharp
public sealed class InMemoryTimeStampAuthority : IUserTimeStampAuthority
{
    private readonly Func<PdfTimestampRequest, CancellationToken, ValueTask<ReadOnlyMemory<byte>>> handler;

    public InMemoryTimeStampAuthority(
        Func<PdfTimestampRequest, CancellationToken, ValueTask<ReadOnlyMemory<byte>>> handler)
    {
        this.handler = handler;
    }

    public ValueTask<ReadOnlyMemory<byte>> TimestampCmsAsync(
        PdfTimestampRequest request,
        CancellationToken cancellationToken = default)
    {
        return handler(request, cancellationToken);
    }
}
```

In tests, that handler can:

- generate an RFC 3161 response entirely in memory
- return a fixture token
- or simply return a deterministically timestamped CMS value for repeatable assertions

## Summary

The real implementation cost is not the cryptography callback. It is the append-only PDF revision writer and placeholder patching needed to produce a stable signed byte range. Once that infrastructure exists, the public API can stay small and centered on a single `IPdfSignatureProvider` interface whose two responsibilities are:

- create the detached CMS signature
- optionally return a timestamped version of that CMS signature