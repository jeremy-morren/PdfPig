# PDF Signing Branch Audit

Review of commit `f41d2334` ("Implemented PDF signing") on the `signing` branch, compared against `origin/master`. Reviewed 2026-08-28.

Scope: full read of the signing/verification implementation (`src/UglyToad.PdfPig/Signing/*`, tokenizer/token changes, parser wiring), a survey of the new test suites and fixtures, and a review of `AcroFieldWriter`, writer/periphery changes, and build/packaging changes.

**Status: signing works** — the public API is fully wired and all 52 signing + AcroFieldWriter tests pass on net8.0, including RSA/ECDSA end-to-end sign-then-verify and a two-signature incremental update preserving the first signature's bytes. The issues below should be addressed before opening a pull request.

**Progress:** see [Done](#done) for items fixed since the audit was written. One blocker remains: §1.5 (`SerializedLength` vs `TokenWriter`).

---

## 1. Security findings

### Blocking

> §1.1 (chain validation time), §1.2 (`IsValid` and document coverage), §1.3 (positional ByteRange gap check) and §1.4 (encryption guard) were in this section and are now fixed — see [Done](#done). §1.5 is the only blocking item left.

#### 1.5 `SerializedLength` can disagree with what `TokenWriter` writes

For strings containing chars > 255, `StringToken.GetCanonicalSerializedLength` charges 4 bytes per char, while `TokenWriter.WriteString` re-encodes as UTF-16BE with a BOM (each byte then octal-escaped). `SerializedLength` feeds the ByteRange coverage check, so a mismatch is a verification-correctness hazard.

### Lower severity

- ~~**EKU policy is both too strict and nonstandard.**~~ **FIXED** — and it was not theoretical. See [Done](#done): a real U.S. Government Publishing Office PDF, signed by the DigiCert Document Signing CA and currently valid, was rejected outright.
- **Large-file overflow:** `CreateContentToSign` casts offsets to `int` (`PdfSigner.cs:490-491`) — breaks on files ≥ 2 GB. Signing also buffers the entire file in memory twice (`GetSourceBytes` plus the signing snapshot).
- **Parsing robustness regression:** the new `serializedLength` bookkeeping makes `HexTokenizer` throw `ArgumentOutOfRangeException` on a truncated `<ABC` at EOF where it previously returned a token (`HexTokenizer.cs:20-46` plus the `HexToken` constructor guard). Similar risk shape in `StringTokenizer` for `(` at EOF.
- **Xref-stream sources:** the signer always appends a classic xref *table* whose `/Prev` may point at an xref *stream*. No guard, no test; some strict readers may reject the output. Should be either supported, tested, or explicitly refused.
- Trivial: the second error message in `ReadSignedContent` interpolates `{Length1}` where it means `{Length2}` (`PdfDocumentSignatures.cs:821`).

### Reviewed and found sound

- Trust-model defaults: online revocation, unknown-revocation fails closed, signer and TSA trust separated, custom-root handling correct on both the .NET (`CustomRootTrust`) and .NET Framework (ExtraStore + post-hoc root-thumbprint check) paths.
- `/ByteRange` bounds checks reject negative values, overlaps with the contents span, and ranges beyond EOF; total signed length is bounded by document length (no allocation amplification).
- Trailing-zero padding after the DER CMS payload in `/Contents` is verified to be all zeros before decoding.
- Timestamp tokens are verified against the actual CMS signature value (message imprint recomputed and compared), with `TimeStampBeforeSigning` checked.
- Signature discovery walks the full AcroForm field tree including nested/inherited fields, using fully qualified field names.

---

## 2. Missing tests

Most of these gaps have since been closed — see [Done](#done) for the tests added. What remains open:

- **No revocation coverage.** `SigningCertificateRevoked` and `TimeStampCertificateRevoked` are still unasserted, and every test forces `RevocationMode = NoCheck`. Exercising them means serving a CRL or OCSP response, which would make the suite depend on a network service; it needs a local responder or a pre-baked CRL fixture to do properly.
- **`ContentsInvalid` is unasserted.** Triggering it needs `/Contents` present but holding neither a hex nor a literal string, which no length-preserving edit to a signed file produces cleanly.
- **Two enum members are unreachable in the current implementation**: `SignatureDictionaryMissing` is never returned (fields with no signature value are skipped in `GetParsedSignatures`), and `Unknown` is never assigned. `SigningCertificateMissing` is only reachable via the zero-signers branch, since `CheckSignature` fails first when no certificate is embedded. Either wire them up or delete them.
- **No signing of xref-stream, linearized, or pre-existing-incremental-history source documents.** Encrypted input is now covered (it throws).
- **No cross-tool interop for incremental update** — e.g. sign an iText-produced signed PDF and confirm the prior signature survives.
- **Malformed CMS edge cases** still thin: no zero/multiple SignerInfos, mismatched messageDigest attribute, truncated DER, or RSASSA-PSS. Attached-content CMS is now covered.
- **Fixture expiry:** the checked-in certificates are valid for 10 years from generation, so those tests will fail wholesale around 2035. There is no guard or regeneration note. The tests added since generate certificates at runtime and are not affected.
- **Dead fixtures:** `pdfs/signed/ecdsa-leaf-valid-p256|p384|p521.pdf` are still referenced by zero tests. Everything under `pdfs/timestamped/` is now used — see [Done](#done).
- **No real-world fixture for an expired signer rescued by its timestamp.** Covered in memory; see [Done](#done) for why no committable document was found and how to generate one.
- **`ETSI.RFC3161` document timestamps are unsupported**, so PAdES-B-LT/LTA archive timestamps are not read. `adbe.pkcs7.sha1` and `adbe.x509.rsa_sha1` are also unsupported; both are legacy and SHA-1 based. PAdES `ETSI.CAdES.detached` is now verified — see [Done](#done).
- Provider-throws and provider-returns-empty are untested. `CancellationToken` is deliberately not tested: it is passed straight through to the caller's provider and PdfPig does not act on it.
- Latent bugs a test would have caught (see §3): `AcroFieldWriter` list box with no selection throws `KeyNotFoundException`; indirect `/Fields` arrays are rejected.

---

## 3. AcroFieldWriter findings

`AcroFieldWriter` is an orthogonal public feature (~700 lines, ~10 new public types) bundled into the signing commit. It rebuilds the whole document page-by-page rather than appending — so it drops `/Info`, `/Names`, `/OpenAction`, outlines, XMP metadata, structure tree, and encryption, and **invalidates any existing signature**. It is not used by `PdfSigner` or mentioned in the docs. Strong candidate to split into its own PR.

Concrete bugs:

- `AcroFieldWriter.cs:421-426` — guaranteed `KeyNotFoundException` for a list box with no selection (the default path: `selectedOptions` defaults to empty and the `_` switch arm reads a `/V` key that was never set).
- `AcroFieldWriter.cs:316-325` — throws when an existing AcroForm's `/Fields` is an indirect reference, which is common in real PDFs.
- `AcroFieldWriter.cs:332-352` — generated AcroForm has no `/DA`/`/DR` (required for variable-text fields per PDF 32000-1 §12.7.3.3), and widgets get no `/AP` and no Print flag; button/checkbox/radio widgets will be invisible in most viewers despite `NeedAppearances`.
- `AcroFieldWriter.cs:691` — arbitrary state names pass through `NameToken.Create` and `(byte)c` truncation; chars > 255 silently mangled.
- `CheckboxesFieldDefinition` supports only one checked box per group (single `/V`) — radio semantics, not checkbox semantics.
- No `/V /Off` written when no widget in a group is active.

---

## 4. Build, packaging, and hygiene

- **Repo-wide warning suppression:** `src/Directory.Build.targets` adds `<NoWarn>CS1591;CS8604;CS8625;CS8600;CS8618</NoWarn>` to every project, silencing missing-XML-doc and four nullable warnings across untouched code. Most likely point of maintainer pushback; it also hides that the new `AcroFieldWriter.FieldDefinitions.cs` public members have no XML docs.
- **Unconditional new package dependencies** in `UglyToad.PdfPig.csproj`: `System.Formats.Asn1 8.0.1`, `System.Security.Cryptography.Pkcs 8.0.1`, `System.Threading.Tasks.Extensions 4.5.4` on all TFMs. PdfPig currently ships dependency-free; these should be conditioned to the frameworks that need them (netstandard2.0/net462/net472).
- **TFM change `net471` → `net472`** in the library and test project. Needed for the Pkcs APIs, but it drops a shipped target (net471 consumers silently fall back to netstandard2.0) and needs an explicit call-out in the PR.
- **SDK pin vs CI mismatch:** new `src/global.json` pins SDK `9.0.0` (`rollForward: latestFeature`) and `tools/global.json` moves to 9.0.0, but `.github/workflows/build_and_test.yml` installs only 2.1/6.0/8.0 — CI will break as configured. Both global.json files lack a trailing newline.
- **`PublicApiScannerTests.cs`:** `UglyToad.PdfPig.AcroForms.Fields.AcroSignatureValue` is listed **twice**, and the `Signing.*` block is inserted out of the file's alphabetical order (and is internally unsorted).
- **Private keys committed:** test fixture `*.key.pem` files (and locally generated `.pfx`, which are gitignored) are now in source control. Test-only material, but worth a note in the PR description.
- **Drive-by refactors to split out:** `XObjectFactory.cs` (pure whitespace/nullability churn), Fonts nullability sweep (`TrueTypeFont.Name` becoming `string?` is a source-compat nuisance), `Page.GetText()` LINQ rewrite (perf regression in a hot path), polyfill relocation to shared `src/Polyfills/` (defensible but belongs in its own PR; note `MemberNotNullAttribute` is guarded `#if !NET && !NETSTANDARD2_1` while `MemberNotNullWhenAttribute` is `#if !NET` — inconsistent), `DictionaryToken.cs` line-ending renormalization, `DirectObjectFinder.cs` blank-line-only diff.
- Minor code issues: `AdvancedPdfDocumentAccess.FindDirectObject<T>` omits the `GuardDisposed()` call every sibling method has; `PdfExtensions.cs:145,184` allows null entries into `DictionaryToken`/`ArrayToken` and the `[return: NotNullIfNotNull]` on `ResolveInternal` is a false promise; `PdfDedupStreamWriter.Equals(byte[]?, byte[]?)` advertises nullability without a null contract in the body.
- Pre-existing uncommitted working-tree changes (not part of this commit, left untouched): `docs/index.md` code-fence reformatting and `.gitattributes`.

---

## 5. Documentation changes made during this audit

- Deleted `docs/pdf-signing.md` (the original design draft).
- Created `docs/Signing.md` — wiki-ready guide covering signing, provider implementation, options, multi-signature flow, verification, trust models, timestamps, and current limitations (including the `CoversEntireDocument` caveat).
- Replaced the README's design-doc link with a "Digital Signatures" section pointing at the new guide.

---

## 6. Suggested order of work before the PR

1. Finish the blocking security items — §1.1, §1.2, §1.3 and §1.4 are [done](#done), along with the EKU policy. Remaining: §1.5 (`SerializedLength` vs `TokenWriter`), which is mechanical.
2. ~~Add a content-tampering test asserting `SignatureMismatch`, plus expired-cert and wrong-root fixtures.~~ Done. Remaining test work: revocation (needs a local CRL/OCSP fixture), xref-stream sources, cross-tool interop.
3. Decide the xref-stream story (support, or refuse with a clear error) and test it.
4. Condition the new package references; fix the global.json/CI mismatch; reconsider the repo-wide NoWarn.
5. Split `AcroFieldWriter` and the drive-by refactors into separate PRs (or fix the AcroFieldWriter bugs and document its rewrite semantics if it stays).
6. Clean up `PublicApiScannerTests` duplicates/ordering and remove or use the dead fixtures.

---

## Done

Fixes applied since the audit was written. Full suite green: **3905 passed, 0 failed, 7 skipped** on net8.0; signing tests also green on net472.

### §1.2 `IsValid` did not imply the signature covers the document

A signature over a partial byte range reported `IsValid == true`; only the separate `CoversEntireDocument` property revealed it, and `ThrowIfInvalid()` did not check it. A caller checking only `IsValid` would trust content the signature never covered.

Naively folding `CoversEntireDocument` into `IsValid` would have been wrong — it is legitimately `false` for every signature but the last in a multiply-signed document, so that would have failed valid files.

**Implementation.** `PdfSignatureError.DocumentModifiedAfterSigning` added. After all signature fields are verified, `FlagContentAppendedAfterSigning` finds the furthest extent (`Offset2 + Length2`) reached by any signature. If that falls short of the file length, the bytes beyond it were appended after every signature was applied, and the signatures sitting at that furthest extent are downgraded to `DocumentModifiedAfterSigning`. Signatures superseded by one reaching further are left valid, and signatures already reporting a more specific failure keep it. `Certificate` and `SigningTime` survive the downgrade so callers can distinguish "signed then modified" from "never signed".

The extent is recorded from inside `VerifySignatureField`, *after* the §1.3 gap check passes, and is carried on every failure path from CMS decoding onward. Two properties follow:

- A signature whose certificate is untrusted still contributes its extent, so it correctly supersedes an earlier valid signature. Deriving the extent only from successful verifications regressed `MixedValidAndInvalidSignaturesReturnMixedResults`, which caught this.
- A signature with a structurally bogus `/ByteRange` contributes nothing, so a forged field claiming to cover the file cannot suppress the flag on a genuine signature.

**Tests.** `SignAsyncValidationReportsContentAppendedAfterTheOutermostSignature` appends bytes to a signed file — everything signed is untouched so the CMS still verifies, and only the coverage check catches it — and asserts `DocumentModifiedAfterSigning`, that `ThrowIfInvalid` throws, and that `Certificate` is still populated. `SignAsyncValidationAcceptsEarlierSignatureSupersededByALaterOne` is the no-false-positive guard: two signatures, the first not covering the file, both valid.

### §1.3 ByteRange gap check was length-only, not positional

`CoversEntireDocument` only checked `Length1 + ContentsFieldValueLength == Offset2`, never that the excluded gap was *where the `/Contents` token sits in the file*. A gap of the right width anywhere in the file passed.

**Implementation.** `SignatureByteRange.ExcludedSpanMatchesContents` reads the bytes actually skipped between the two signed spans and requires them to be exactly the `/Contents` value — delimiters included — whose hex digits decode to the CMS payload being verified. Whitespace is tolerated; literal-string contents, whose escape rules make exact comparison impractical, fall back to a delimiter plus serialized-length match. A mismatch reports `ByteRangeInvalid`. `CoversEntireDocument` reduces to `Offset1 == 0 && Offset2 + Length2 == documentLength`, since gap identity is now established separately.

**Test.** `SignAsyncValidationRejectsByteRangeExcludingASpanOtherThanTheContents` slides the gap 64 bytes earlier, preserving its width and keeping the spans running to EOF. The test asserts the tampered file still satisfies the old length-only invariant, so it documents exactly what regressed, then asserts `ByteRangeInvalid`.

*Not covered:* a case where the parsed `/Contents` resolves from a different object than the gap needs a hand-crafted shadow-update fixture. Worth adding, but larger than a unit test.

### §1.4 No encryption guard when signing

`PdfSigner.SignAsync` never checked `document.IsEncrypted`, so signing an encrypted document wrote plaintext into an encrypted file and emitted a trailer with no `/Encrypt` — silently corrupt output.

**Implementation.** `ValidateOptions` throws `NotSupportedException`, before any bytes reach the output stream.

**Test.** `SignAsyncThrowsForEncryptedDocuments` opens `encrypted-password-is-password.pdf` with its password and asserts both the throw and that the output stream is left empty.

### §1.1 Chain validation used the attacker-claimed signing time

`ValidateCertificate` set `X509Chain.VerificationTime` from the CMS signing-time signed attribute. That attribute is protected only by the signer's own key, so anyone holding an **expired or revoked** certificate could backdate it and have the signature verify as trusted.

**Implementation.** The claimed signing time no longer influences trust; it is still reported for diagnostics. The chain is validated as of now, unless an embedded RFC 3161 token both commits to this signature value and builds to a trusted authority — an assertion the signer cannot forge — in which case that token's generation time is used. `GetTrustedTimeStampTime` performs that check; `TryGetSignerSignature` moved above chain validation to supply the signature value it needs.

The authority's own chain is likewise validated as of now rather than at the time the token asserts, which would let the holder of an expired timestamping certificate vouch for their own backdating.

**Tests.** `VerificationIgnoresABackdatedSigningTimeClaim` signs with an already-expired certificate while claiming a signing time from when it was valid, and asserts `SigningCertificateExpired`. `VerificationValidatesTheSignerChainAtATrustedTimestampTime` is the counterpart: the same expired certificate verifies when a trusted in-memory TSA vouches for the earlier time. `VerificationIgnoresATimestampFromAnUntrustedAuthorityWhenDatingTheSignerChain` confirms an untrusted authority's time is disregarded.

Both negative tests were confirmed load-bearing by temporarily reverting the fix and watching them fail, then restoring it.

**Consequence worth noting:** without a trusted timestamp, a signature whose certificate has since expired is now reported `SigningCertificateExpired`. That is the correct answer absent LTV material, but it changes the verdict on older documents, and it is why the real-world fixture test below is written to skip rather than fail once its certificate ages out.

### Certificate rules are delegated to the caller

Chain building answers "is this certificate from someone I trust". Whether it was *issued for signing documents* is a separate question with no answer PdfPig can hard-code, so it is now an interface:

```csharp
public interface ICertificateValidator
{
    void ValidateCertificate(X509Certificate2 certificate, PdfSignatureSubFilter subFilter);
}
```

Rejection is by throwing `PdfCertificateValidationFailedException`. Verification catches it, reports `PdfSignatureError.CertificateValidationFailed`, and carries the exception on `PdfSignatureVerificationResult.CertificateValidationException` so the validator's own message reaches the caller. `EKUNotValidForSigning` was removed — it described one particular validator's opinion rather than a verification outcome.

`PdfSignatureVerificationOptions.SignatureCertificateValidator` defaults to `DocumentSigningEKUValidator`, `TimeStampCertificateValidator` to `TimeStampingEKUValidator`; either can be set to `null` to apply no rules beyond chain building. `EnhancedKeyUsageValidator` is the reusable base taking any set of OIDs.

This also gives the European qualified-signature ecosystem a way in without PdfPig taking a position: such certificates commonly declare no extended key usage and convey purpose through QCStatements, and a caller can now express that in a few lines. Accepting such a certificate still is not the same as validating a qualified signature under eIDAS, which needs the EU Trusted Lists; the documentation says so explicitly.

Signature trust and timestamp trust remain separate, as the original design intended; the test helper that had collapsed them into one store was reverted.

### PAdES (`ETSI.CAdES.detached`) is now verified

`/SubFilter` is parsed into a `PdfSignatureSubFilter` enum, reported on every result — including for encodings that cannot be verified, so a caller can tell *what* was found rather than just that it was unsupported. The enum is also passed to `ICertificateValidator`, so rules can differ by signature kind.

Both verified encodings carry a detached CMS signature over the byte ranges, so the existing path is reused wholesale; the branch between them is one flag. The addition is the ESS signing-certificate attribute (`signingCertificate` and `signingCertificateV2`), which binds the certificate the signer intended into the signed data and stops a signature being re-presented with a different certificate carrying the same key. It is verified wherever it appears and **required** for CAdES, which is what the profile demands.

Restructuring while here: `VerifySignatureField` had fifteen near-identical result constructions differing only in error and message. They now go through one local function closing over the field name, subfilter and coverage facts, which is what made adding two more result fields tractable. `TryRunCertificateValidator` is shared between the signature path, the timestamp path and the trusted-time path.

**Tests.** A CAdES signature with the attribute verifies and reports `CAdESDetached`; one without it is rejected; an attribute committing to a *different* certificate is rejected, which is the substitution the attribute exists to prevent. Plus: a custom validator's exception reaching the result, the subfilter being handed to the validator, a null validator disabling the check, and a recognised-but-unverified subfilter (`adbe.pkcs7.sha1`) reporting its enum value.

**Still unsupported:** `ETSI.RFC3161` document timestamps, `adbe.pkcs7.sha1` and `adbe.x509.rsa_sha1`.

### Timestamp authority certificates are dated by the token

The §1.1 work initially validated the authority's chain as of now, on the reasoning that a certificate should not vouch for its own asserted time. That is too strict to be correct: a timestamp exists precisely so a signature outlives the certificates involved, and validating the authority as of now rejects every archived timestamp. Authority chains are now validated as of the token's generation time, which is what validators do in practice. The load-bearing part of §1.1 is unaffected — the *signer's* chain is still never dated by the signer's own claim, only by a third party's.

The residual exposure, forging a timestamp with a compromised historical authority key, needs long-term validation material to detect and is documented as out of scope.

### EKU policy rejected legitimately signed documents

Recorded in the original audit as lower severity and theoretical. Testing the system trust store proved it real: a U.S. Government Publishing Office PDF from govinfo.gov, signed by the **DigiCert Document Signing CA** and valid until March 2027, was rejected with `EKUNotValidForSigning`.

Verification hard-required the *code signing* EKU (`1.3.6.1.5.5.7.3.3`). The GPO certificate carries emailProtection (`1.3.6.1.5.5.7.3.4`) and clientAuth — emailProtection being the EKU that certificates issued under the Adobe Approved Trust List and Certified Document Services conventionally use. There is no single OID the ecosystem settled on.

**Implementation.** The default `SignatureEnhancedKeyUsages` accepts `id-kp-documentSigning` (RFC 9336), Adobe's `1.2.840.113583.1.1.5`, emailProtection, codeSigning, and anyExtendedKeyUsage. Certificates with *no* EKU extension are still rejected, which is conservative — RFC 5280 reads an absent extension as unrestricted — and preserves the existing `signed-with-no-eku.pdf` fixture expectation. Callers who disagree can clear the list. The `signed-with-different-eku.pdf` fixture uses clientAuth alone and is still correctly rejected.

**Worth revisiting:** probing real documents showed Polish gazette signatures using *qualified* certificates (Certum QCA) that also fail this check. Qualified certificates often convey purpose through QCStatements rather than an EKU, so rejecting a certificate with no EKU may be wrong for the whole European qualified-signature ecosystem. Left as-is because changing it would flip an existing fixture expectation, and it is now a one-line opt-out for callers.

### System trust store coverage

`SystemTrustStoreValidatesAPubliclyTrustedRealWorldSignature` verifies the GPO document against `UseSystemStore = true`, which is the only way to exercise a real publicly trusted chain end to end. `src/UglyToad.PdfPig.Tests/Integration/SpecificTestDocuments/govinfo-plaw-118publ1-signed.pdf` (176 KB) is Public Law 118-1 — a work of the U.S. Government, public domain under 17 U.S.C. 105, so there is no licensing question in committing it.

Two deliberate choices: revocation is set to `NoCheck` so the test exercises chain building rather than reaching an OCSP responder, and the test is a `SkippableFact` that skips on `SigningCertificateExpired` or `SigningCertificateNotTrusted`. The fixture's certificate expires **March 2027** and the signature carries no timestamp, so under the §1.1 semantics it will age out; skipping keeps CI green and tells the maintainer to refresh the fixture from govinfo.gov. It also covers hosts with no usable root store.

`SystemTrustStoreRejectsASignerItDoesNotKnow` is the deterministic half: an in-memory self-signed certificate must not be trusted by the system store. No network, no fixture, never ages out.

### Signed-and-timestamped documents, and the dead fixtures

The repository already contained signed **and** timestamped PDFs that no test referenced — the audit listed them under dead fixtures. They are now wired up, which covers the signed-and-timestamped case without downloading anything or raising a licensing question:

- `SignedButNotTimestampedDocumentIsValidAndReportsNoTimestamp` — signature valid, `GetTimestampSignatures` returns null.
- `SignedAndTimestampedDocumentsReportBothAsValid` — a Theory over `pdfs/timestamped/{rsa,ecdsa-p256,ecdsa-p384,ecdsa-p521}`, asserting signature and timestamp both valid and the field name carried through. The ECDSA cases chain through the previously unused intermediate. Signature trust and timestamp trust are anchored on different roots here, because these fixtures use an RSA authority whatever signed the document.
- `TimestampFromAnUntrustedAuthorityDoesNotInvalidateTheSignature` — anchors timestamp trust on the signer's root, confirming on real files that the two trust configurations are honoured independently.

That leaves only `pdfs/signed/ecdsa-leaf-valid-*.pdf` unused.

### Not delivered: a real document with an expired signer rescued by its timestamp

Searched for one and could not find a committable candidate. Recording the constraints so the search is not repeated blindly:

- **PdfPig only verifies `adbe.pkcs7.detached`.** Most modern real-world signed PDFs, EU ones especially, are PAdES `ETSI.CAdES.detached`. Probed Polish *Dziennik Ustaw* and *Monitor Polski* documents: every recent signature reports `UnsupportedSubFilter`. EUR-Lex web PDFs are not signed at all.
- **GPO re-signs its whole archive with a current certificate.** A 2012 public law reports a signing time of January 2026 against the 2025–2027 certificate, so govinfo cannot supply an expired signer.
- **Vendor sample pages** (FreeTSA, tecxoft) publish signed and timestamped demos but state no licensing terms, and FreeTSA's root is not publicly trusted. Not appropriate to commit to someone else's OSS repository.
- The PDF Association examples are CC BY-SA 4.0, awkward inside an Apache-2.0 repository, and contain no signed sample. Apache PDFBox's signature resources are unsigned inputs.

The verification path itself is covered by `VerificationValidatesTheSignerChainAtATrustedTimestampTime`, confirmed load-bearing.

**Recommended way to get a real fixture**, if one is wanted: extend `tools/UglyToad.PdfPig.SigningTest` with a backdated timestamp client — `TimeStampTokenGenerator.Generate` already takes the generation time, currently hard-coded to `DateTime.UtcNow` — plus a root and leaf dated in the past. Pin every certificate to fixed absolute dates and put the token's generation time inside the signer's window; because both chains are then validated at that past moment, the fixture never ages out, unlike the GPO document. This was not done here because `SigningScenarioRunner.Run` regenerates every certificate and fixture on each run, so producing one new file would rewrite every committed fixture and bury the change in churn.

### §2 Test coverage

New file `PdfSignatureScenarioTests.cs` — 17 tests on net8.0/net9.0, 11 on net472. Every certificate and timestamp token is generated at runtime in memory: nothing contacts a network service, and none of it inherits the fixture certificates' 2035 expiry.

**Tampering.** `VerificationDetectsModificationOfBytesInsideTheSignedRange` rewrites the `/Reason` string in place — it sits ahead of `/Contents` in the signature dictionary, so it is inside the first signed span and every byte offset is preserved. The byte range still parses and still brackets `/Contents`, so only the CMS digest can catch it. This closes the audit's largest gap: `SignatureMismatch` was previously never asserted. Also `UnsupportedSubFilter` (rewritten to the same-length `ETSI.CAdES.detached`) and `ContentsMissing`.

**A CMS carrying its own attached content is rejected.** `VerificationRejectsCmsCarryingItsOwnAttachedContent` has the provider sign a payload of its own choosing and embed it, rather than signing the PDF byte ranges. Worth calling out because the verifier constructs `new SignedCms(new ContentInfo(signedContent), detached: true)` before `Decode`; had `Decode` let the embedded content win, a signature over arbitrary attacker-chosen bytes would have verified against any document. It does not, and the test pins that.

**Certificate trust.** A signer chaining to a *different* root now reports `SigningCertificateNotTrusted` — distinct from the pre-existing test, which supplies no roots at all and short-circuits before a chain is built. `SigningCertificateExpired` is covered by signing with a genuinely expired certificate rather than by backdating a claimed signing time, so the test stays meaningful once §1.1 is fixed. A leaf → intermediate → root chain verifies with the intermediate supplied only through `AdditionalIntermediateCertificates`.

**Digest algorithms.** SHA-384 and SHA-512 round-trip, where only SHA-256 was exercised before.

**RFC 3161 timestamps, issued in memory.** `CreateTimestampToken` builds a TSTInfo with `AsnWriter`, wraps it in a `SignedCms` with the id-ct-TSTInfo content type, and attaches it as the id-aa-signatureTimeStampToken unsigned attribute — a real token, where the previous test double returned the CMS unchanged and never exercised the embedding path. Covers the valid case (`TimeStampTime` populated, field name carried through) plus `TimeStampTokenMismatch`, `TimeStampBeforeSigning`, `TimeStampTokenInvalid`, and `TimeStampCertificateNotTrusted` both from an untrusted authority and from a TSA certificate lacking the timeStamping EKU. The untrusted-authority test also pins that signer trust and timestamp trust are independent: the signature stays valid while the timestamp is rejected.

These six tests are `#if NET`. Issuing a token needs `Rfc3161TimestampRequest` and `SignerInfo.AddUnsignedAttribute`; on .NET Framework the compiler binds to the framework's own `System.Security.Cryptography.Pkcs` assembly, which predates both, and an explicit `PackageReference` does not override it. The verification code they exercise is not conditional and runs identically on every target framework.

**Read API.** `GetSignatures` returns the same verdict when called repeatedly (verification seeks around the input bytes, so a stale stream position would surface here), and page text stays readable after signing.

*Side note:* the compile failure above is worth a second look on its own. If the test project binds to the framework's old Pkcs assembly on net472, the library plausibly does too, which would make its `System.Security.Cryptography.Pkcs 8.0.1` package reference inert at compile time on that target. It works today because the verifier only uses APIs the old assembly already has, but it is worth confirming before shipping — and it interacts with the packaging concerns in §4.

### Documentation

`docs/Signing.md` gained a "Content appended after signing" section explaining that `IsValid` now accounts for unsigned trailing content (so checking it alone is safe), that superseded signatures stay valid, and that PdfPig has no DocMDP support and so treats any uncovered trailing content as a modification. The `CoversEntireDocument` bullet was rewritten from "always check this" to a diagnostic property, the verification-requirements list gained the gap-identity rule, and the encryption limitation now names the thrown exception.
