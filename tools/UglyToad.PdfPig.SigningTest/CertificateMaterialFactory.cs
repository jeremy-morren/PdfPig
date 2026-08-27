using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace UglyToad.PdfPig.SigningTest;

internal sealed class CertificateMaterialFactory
{
    public const string PfxPassword = "pdfpig-signing-test";

    private static readonly Oid CodeSigningOid = new("1.3.6.1.5.5.7.3.3", "Code Signing");
    private static readonly Oid TimeStampingOid = new("1.3.6.1.5.5.7.3.8", "Time Stamping");
    private static readonly Oid ClientAuthenticationOid = new("1.3.6.1.5.5.7.3.2", "Client Authentication");

    public GeneratedCertificates CreateAll()
    {
        var now = DateTimeOffset.UtcNow;
        var notBefore = now.AddDays(-7);
        var notAfter = now.AddYears(10);

        var rsaRoot = CreateRsaCertificate(
            baseName: "rsa-root-valid",
            subjectName: "CN=PdfPig Signing Test RSA Root",
            description: "Valid RSA root CA certificate. Self-signed. Includes both code-signing and time-stamping EKUs.",
            notBefore,
            notAfter,
            isCertificateAuthority: true,
            includeCodeSigning: true,
            includeTimeStamping: true,
            issuer: null,
            curve: null);

        var rsaLeaf = CreateRsaCertificate(
            baseName: "rsa-leaf-valid",
            subjectName: "CN=PdfPig Signing Test RSA Leaf",
            description: "Valid RSA leaf certificate for PDF signing. Issued by rsa-root-valid. Includes both code-signing and time-stamping EKUs.",
            notBefore,
            notAfter,
            isCertificateAuthority: false,
            includeCodeSigning: true,
            includeTimeStamping: true,
            issuer: rsaRoot,
            curve: null);

        var rsaTimestampLeaf = CreateRsaCertificate(
            baseName: "rsa-tsa-leaf-valid",
            subjectName: "CN=PdfPig Signing Test RSA TSA Leaf",
            description: "Valid RSA TSA leaf certificate. Issued by rsa-root-valid. Contains only the time-stamping EKU because RFC 3161 timestamp generation rejects mixed EKUs.",
            notBefore,
            notAfter,
            isCertificateAuthority: false,
            includeCodeSigning: false,
            includeTimeStamping: true,
            issuer: rsaRoot,
            curve: null,
            enhancedKeyUsageOverride: CreateEnhancedKeyUsageCollection(TimeStampingOid));

        var ecdsaRoot = CreateEcdsaCertificate(
            baseName: "ecdsa-root-valid-p384",
            subjectName: "CN=PdfPig Signing Test ECDSA Root P-384",
            description: "Valid ECDSA root CA certificate on the NIST P-384 curve. Self-signed. Includes both code-signing and time-stamping EKUs.",
            notBefore,
            notAfter,
            isCertificateAuthority: true,
            includeCodeSigning: true,
            includeTimeStamping: true,
            issuer: null,
            curve: ECCurve.NamedCurves.nistP384);

        var ecdsaIntermediate = CreateEcdsaCertificate(
            baseName: "ecdsa-intermediate-valid-p384",
            subjectName: "CN=PdfPig Signing Test ECDSA Intermediate P-384",
            description: "Valid ECDSA intermediate CA certificate on the NIST P-384 curve. Issued by ecdsa-root-valid-p384. Includes both code-signing and time-stamping EKUs.",
            notBefore,
            notAfter,
            isCertificateAuthority: true,
            includeCodeSigning: true,
            includeTimeStamping: true,
            issuer: ecdsaRoot,
            curve: ECCurve.NamedCurves.nistP384);

        var ecdsaLeafP256 = CreateEcdsaCertificate(
            baseName: "ecdsa-leaf-valid-p256",
            subjectName: "CN=PdfPig Signing Test ECDSA Leaf P-256",
            description: "Valid ECDSA leaf certificate on the NIST P-256 curve for PDF signing. Issued by ecdsa-intermediate-valid-p384. Includes both code-signing and time-stamping EKUs.",
            notBefore,
            notAfter,
            isCertificateAuthority: false,
            includeCodeSigning: true,
            includeTimeStamping: true,
            issuer: ecdsaIntermediate,
            curve: ECCurve.NamedCurves.nistP256);

        var ecdsaLeafP384 = CreateEcdsaCertificate(
            baseName: "ecdsa-leaf-valid-p384",
            subjectName: "CN=PdfPig Signing Test ECDSA Leaf P-384",
            description: "Valid ECDSA leaf certificate on the NIST P-384 curve for PDF signing. Issued by ecdsa-intermediate-valid-p384. Includes both code-signing and time-stamping EKUs.",
            notBefore,
            notAfter,
            isCertificateAuthority: false,
            includeCodeSigning: true,
            includeTimeStamping: true,
            issuer: ecdsaIntermediate,
            curve: ECCurve.NamedCurves.nistP384);

        var ecdsaLeafP521 = CreateEcdsaCertificate(
            baseName: "ecdsa-leaf-valid-p521",
            subjectName: "CN=PdfPig Signing Test ECDSA Leaf P-521",
            description: "Valid ECDSA leaf certificate on the NIST P-521 curve for PDF signing. Issued by ecdsa-intermediate-valid-p384. Includes both code-signing and time-stamping EKUs.",
            notBefore,
            notAfter,
            isCertificateAuthority: false,
            includeCodeSigning: true,
            includeTimeStamping: true,
            issuer: ecdsaIntermediate,
            curve: ECCurve.NamedCurves.nistP521);

        var invalidNoEku = CreateRsaCertificate(
            baseName: "invalid-rsa-no-eku",
            subjectName: "CN=PdfPig Signing Test Invalid RSA No EKU",
            description: "Invalid RSA leaf certificate. Self-signed. Intentionally omits both code-signing and time-stamping EKUs.",
            notBefore,
            notAfter,
            isCertificateAuthority: false,
            includeCodeSigning: false,
            includeTimeStamping: false,
            issuer: null,
            curve: null,
            omitEnhancedKeyUsage: true);

        var invalidDifferentEku = CreateRsaCertificate(
            baseName: "invalid-rsa-different-eku",
            subjectName: "CN=PdfPig Signing Test Invalid RSA Different EKU",
            description: "Invalid RSA leaf certificate. Self-signed. Uses an unrelated EKU (client authentication) instead of code signing.",
            notBefore,
            notAfter,
            isCertificateAuthority: false,
            includeCodeSigning: false,
            includeTimeStamping: false,
            issuer: null,
            curve: null,
            enhancedKeyUsageOverride: CreateEnhancedKeyUsageCollection(ClientAuthenticationOid));

        return new GeneratedCertificates(
            [rsaRoot, rsaLeaf, rsaTimestampLeaf, ecdsaRoot, ecdsaIntermediate, ecdsaLeafP256, ecdsaLeafP384, ecdsaLeafP521],
            [rsaLeaf, ecdsaLeafP256, ecdsaLeafP384, ecdsaLeafP521],
            [invalidNoEku, invalidDifferentEku],
            rsaTimestampLeaf,
            invalidNoEku,
            invalidDifferentEku,
            rsaLeaf);
    }

    private static CertificateMaterial CreateRsaCertificate(
        string baseName,
        string subjectName,
        string description,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        bool isCertificateAuthority,
        bool includeCodeSigning,
        bool includeTimeStamping,
        CertificateMaterial? issuer,
        ECCurve? curve,
        bool omitEnhancedKeyUsage = false,
        OidCollection? enhancedKeyUsageOverride = null)
    {
        using var rsa = RSA.Create(3072);
        var request = new CertificateRequest(
            subjectName,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        ConfigureRequest(
            request,
            rsa,
            isCertificateAuthority,
            includeCodeSigning,
            includeTimeStamping,
            omitEnhancedKeyUsage,
            enhancedKeyUsageOverride);

        return CreateCertificate(baseName, description, request, rsa, notBefore, notAfter, issuer, isCertificateAuthority);
    }

    private static CertificateMaterial CreateEcdsaCertificate(
        string baseName,
        string subjectName,
        string description,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        bool isCertificateAuthority,
        bool includeCodeSigning,
        bool includeTimeStamping,
        CertificateMaterial? issuer,
        ECCurve curve,
        OidCollection? enhancedKeyUsageOverride = null)
    {
        using var ecdsa = ECDsa.Create(curve);
        var request = new CertificateRequest(
            subjectName,
            ecdsa,
            HashAlgorithmName.SHA384);

        ConfigureRequest(
            request,
            ecdsa,
            isCertificateAuthority,
            includeCodeSigning,
            includeTimeStamping,
            omitEnhancedKeyUsage: false,
            enhancedKeyUsageOverride);

        return CreateCertificate(baseName, description, request, ecdsa, notBefore, notAfter, issuer, isCertificateAuthority);
    }

    private static void ConfigureRequest(
        CertificateRequest request,
        AsymmetricAlgorithm key,
        bool isCertificateAuthority,
        bool includeCodeSigning,
        bool includeTimeStamping,
        bool omitEnhancedKeyUsage,
        OidCollection? enhancedKeyUsageOverride)
    {
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: isCertificateAuthority,
                hasPathLengthConstraint: isCertificateAuthority,
                pathLengthConstraint: isCertificateAuthority ? 1 : 0,
                critical: true));

        var keyUsage = isCertificateAuthority
            ? X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign
            : X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation;

        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        if (!omitEnhancedKeyUsage)
        {
            var eku = enhancedKeyUsageOverride ?? CreateEnhancedKeyUsageCollection(
                includeCodeSigning ? CodeSigningOid : null,
                includeTimeStamping ? TimeStampingOid : null);

            if (eku.Count > 0)
            {
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
            }
        }
    }

    private static OidCollection CreateEnhancedKeyUsageCollection(params Oid?[] usages)
    {
        var collection = new OidCollection();
        foreach (var usage in usages)
        {
            if (usage is not null)
            {
                collection.Add(usage);
            }
        }

        return collection;
    }

    private static CertificateMaterial CreateCertificate(
        string baseName,
        string description,
        CertificateRequest request,
        AsymmetricAlgorithm subjectKey,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        CertificateMaterial? issuer,
        bool isCertificateAuthority)
    {
        var serialNumber = CreateSerialNumber();
        var privateKeyPkcs8Bytes = ExportPrivateKeyPkcs8(subjectKey);
        var privateKeyPem = ExportPrivateKeyPem(subjectKey);

        using var createdCertificate = issuer is null
            ? request.CreateSelfSigned(notBefore, notAfter)
            : request.Create(issuer.Certificate, notBefore, notAfter, serialNumber);

        using var certificateWithKey = AttachPrivateKey(createdCertificate, subjectKey);
        var exportableCertificate = ExportAsReloadedPfx(certificateWithKey);

        IReadOnlyList<X509Certificate2> chain = issuer is null
            ? [exportableCertificate]
            : [exportableCertificate, .. issuer.Chain];

        return new CertificateMaterial(baseName, description, exportableCertificate, chain, privateKeyPkcs8Bytes, privateKeyPem);
    }

    private static X509Certificate2 AttachPrivateKey(X509Certificate2 certificate, AsymmetricAlgorithm key)
    {
        return key switch
        {
            RSA rsa => certificate.HasPrivateKey ? new X509Certificate2(certificate) : certificate.CopyWithPrivateKey(rsa),
            ECDsa ecdsa => certificate.HasPrivateKey ? new X509Certificate2(certificate) : certificate.CopyWithPrivateKey(ecdsa),
            _ => throw new NotSupportedException($"Unsupported key algorithm: {key.GetType().Name}.")
        };
    }

    private static X509Certificate2 ExportAsReloadedPfx(X509Certificate2 certificate)
    {
        var bytes = certificate.Export(X509ContentType.Pfx, PfxPassword);
        return new X509Certificate2(bytes, PfxPassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
    }

    private static byte[] CreateSerialNumber()
    {
        Span<byte> serial = stackalloc byte[16];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;
        return serial.ToArray();
    }

    private static byte[] ExportPrivateKeyPkcs8(AsymmetricAlgorithm key)
    {
        return key switch
        {
            RSA rsa => rsa.ExportPkcs8PrivateKey(),
            ECDsa ecdsa => ecdsa.ExportPkcs8PrivateKey(),
            _ => throw new NotSupportedException($"Unsupported key algorithm: {key.GetType().Name}.")
        };
    }

    private static string ExportPrivateKeyPem(AsymmetricAlgorithm key)
    {
        return key switch
        {
            RSA rsa => rsa.ExportPkcs8PrivateKeyPem(),
            ECDsa ecdsa => ecdsa.ExportPkcs8PrivateKeyPem(),
            _ => throw new NotSupportedException($"Unsupported key algorithm: {key.GetType().Name}.")
        };
    }
}

internal sealed record GeneratedCertificates(
    IReadOnlyList<CertificateMaterial> ValidAll,
    IReadOnlyList<CertificateMaterial> ValidLeafs,
    IReadOnlyList<CertificateMaterial> InvalidAll,
    CertificateMaterial ValidTimestampAuthority,
    CertificateMaterial InvalidNoEnhancedKeyUsage,
    CertificateMaterial InvalidDifferentEnhancedKeyUsage,
    CertificateMaterial ControlLeaf);
