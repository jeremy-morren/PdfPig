namespace UglyToad.PdfPig.Signing;

using System.Security.Cryptography;

/// <summary>
/// Requires a timestamp authority certificate to declare the <c>timeStamping</c> extended key usage,
/// which RFC 3161 demands of a timestamp authority. This is the default
/// <see cref="ICertificateValidator"/> for timestamps.
/// </summary>
public sealed class TimeStampingEKUValidator : EnhancedKeyUsageValidator
{
    /// <summary>
    /// <c>id-kp-timeStamping</c>.
    /// </summary>
    public const string TimeStampingOid = "1.3.6.1.5.5.7.3.8";

    /// <summary>
    /// Creates a new <see cref="TimeStampingEKUValidator"/>.
    /// </summary>
    public TimeStampingEKUValidator() : base(new Oid(TimeStampingOid, "Time Stamping"))
    {
    }
}
