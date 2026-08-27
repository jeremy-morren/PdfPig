using System.Security.Cryptography.X509Certificates;
using iText.Bouncycastle.Crypto;
using iText.Bouncycastle.X509;
using iText.Commons.Bouncycastle.Cert;
using iText.Commons.Bouncycastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace UglyToad.PdfPig.SigningTest;

internal sealed class CertificateMaterial
{
    public CertificateMaterial(
        string baseName,
        string description,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        byte[] privateKeyPkcs8Bytes,
        string privateKeyPem)
    {
        BaseName = baseName;
        Description = description;
        Certificate = certificate;
        Chain = chain;
        PrivateKeyPkcs8Bytes = privateKeyPkcs8Bytes;
        PrivateKeyPem = privateKeyPem;
    }

    public string BaseName { get; }

    public string Description { get; }

    public X509Certificate2 Certificate { get; }

    public IReadOnlyList<X509Certificate2> Chain { get; }

    public byte[] PrivateKeyPkcs8Bytes { get; }

    public string PrivateKeyPem { get; }

    public IX509Certificate[] GetITextChain() =>
        Chain.Select(ToITextCertificate).Cast<IX509Certificate>().ToArray();

    public IPrivateKey GetITextPrivateKey() => new PrivateKeyBC(GetBouncyCastlePrivateKey());

    public Org.BouncyCastle.X509.X509Certificate GetBouncyCastleCertificate()
    {
        var parser = new X509CertificateParser();
        return parser.ReadCertificate(Certificate.Export(X509ContentType.Cert));
    }

    public IStore<Org.BouncyCastle.X509.X509Certificate> GetBouncyCastleCertificateStore()
    {
        return CollectionUtilities.CreateStore(Chain.Select(ToBouncyCastleCertificate));
    }

    public Org.BouncyCastle.Crypto.AsymmetricKeyParameter GetBouncyCastlePrivateKey()
    {
        return PrivateKeyFactory.CreateKey(PrivateKeyPkcs8Bytes);
    }

    private static Org.BouncyCastle.X509.X509Certificate ToBouncyCastleCertificate(X509Certificate2 certificate)
    {
        var parser = new X509CertificateParser();
        return parser.ReadCertificate(certificate.Export(X509ContentType.Cert));
    }

    private static X509CertificateBC ToITextCertificate(X509Certificate2 certificate)
    {
        return new X509CertificateBC(ToBouncyCastleCertificate(certificate));
    }
}
