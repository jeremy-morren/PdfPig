namespace UglyToad.PdfPig.Signing;

using System;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Produces detached CMS signatures and optional timestamped CMS payloads for PDF signing.
/// </summary>
public interface IPdfSignatureProvider
{
    /// <summary>
    /// Creates a detached CMS signature for the exact byte ranges provided in the signing request.
    /// </summary>
    Task<ReadOnlyMemory<byte>> SignAsync(PdfSigningRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Optionally post-processes a CMS signature, for example by embedding an RFC 3161 timestamp token.
    /// </summary>
    Task<ReadOnlyMemory<byte>?> TimestampAsync(PdfTimestampRequest request, CancellationToken cancellationToken = default);
}