namespace UglyToad.PdfPig.Signing;

using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Requires a certificate to declare at least one of a set of extended key usages.
/// </summary>
/// <remarks>
/// A certificate carrying no extended key usage extension at all is rejected. RFC 5280 reads an absent
/// extension as placing no restriction on the certificate, so callers who want that reading, or who are
/// working with certificates that declare their purpose some other way, should use a different
/// <see cref="ICertificateValidator"/>.
/// </remarks>
public class EnhancedKeyUsageValidator : ICertificateValidator
{
    /// <summary>
    /// The extended key usages, one of which the certificate must declare.
    /// </summary>
    public IReadOnlyList<Oid> AcceptedEnhancedKeyUsages { get; }

    /// <summary>
    /// Creates a new <see cref="EnhancedKeyUsageValidator"/>.
    /// </summary>
    /// <param name="acceptedEnhancedKeyUsages">The extended key usages to accept.</param>
    public EnhancedKeyUsageValidator(params Oid[] acceptedEnhancedKeyUsages)
        : this((IEnumerable<Oid>)acceptedEnhancedKeyUsages)
    {
    }

    /// <summary>
    /// Creates a new <see cref="EnhancedKeyUsageValidator"/>.
    /// </summary>
    /// <param name="acceptedEnhancedKeyUsages">The extended key usages to accept.</param>
    public EnhancedKeyUsageValidator(IEnumerable<Oid> acceptedEnhancedKeyUsages)
    {
        if (acceptedEnhancedKeyUsages is null)
        {
            throw new ArgumentNullException(nameof(acceptedEnhancedKeyUsages));
        }

        AcceptedEnhancedKeyUsages = acceptedEnhancedKeyUsages.ToArray();

        if (AcceptedEnhancedKeyUsages.Count == 0)
        {
            throw new ArgumentException("At least one accepted enhanced key usage must be provided.", nameof(acceptedEnhancedKeyUsages));
        }
    }

    /// <inheritdoc />
    public virtual void ValidateCertificate(X509Certificate2 certificate, PdfSignatureSubFilter subFilter)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        var declared = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(x => x.EnhancedKeyUsages.Cast<Oid>())
            .Select(x => x.Value)
            .Where(x => x != null)
            .ToArray();

        if (declared.Length == 0)
        {
            throw new PdfCertificateValidationFailedException(
                $"The certificate '{certificate.Subject}' declares no enhanced key usage. Expected one of: {DescribeAccepted()}.");
        }

        if (declared.Any(x => AcceptedEnhancedKeyUsages.Any(accepted => string.Equals(accepted.Value, x, StringComparison.Ordinal))))
        {
            return;
        }

        throw new PdfCertificateValidationFailedException(
            $"The certificate '{certificate.Subject}' declares the enhanced key usages {string.Join(", ", declared)}, none of which is accepted. Expected one of: {DescribeAccepted()}.");
    }

    private string DescribeAccepted() =>
        string.Join(", ", AcceptedEnhancedKeyUsages.Select(x => x.FriendlyName is null ? x.Value : $"{x.Value} ({x.FriendlyName})"));
}
