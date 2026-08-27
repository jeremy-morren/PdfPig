namespace UglyToad.PdfPig.Signing;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AcroForms;
using Content;
using Core;
using Tokens;
using Writer;

/// <summary>
/// Creates append-only PDF signature revisions.
/// </summary>
public static class PdfSigner
{
    private const int ByteRangeNumberWidth = 20;

    /// <summary>
    /// Appends a new signed revision to the provided output stream.
    /// </summary>
    public static async ValueTask SignAsync(
        PdfDocument document,
        Stream output,
        IPdfSignatureProvider signatureProvider,
        PdfSignatureOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (document is null)
        {
            throw new ArgumentNullException(nameof(document));
        }

        if (output is null)
        {
            throw new ArgumentNullException(nameof(output));
        }

        if (signatureProvider is null)
        {
            throw new ArgumentNullException(nameof(signatureProvider));
        }

        options ??= new PdfSignatureOptions();
        ValidateOptions(document, options);

        var sourceBytes = document.GetSourceBytes();
        if (output.CanSeek)
        {
            output.Seek(0, SeekOrigin.Begin);
            output.SetLength(0);
        }

        await output.WriteAsync(sourceBytes, 0, sourceBytes.Length, cancellationToken).ConfigureAwait(false);

        var session = new IncrementalSigningSession(document, output, options);
        var placeholder = session.WriteRevision();
        placeholder.PatchByteRange();

        var request = new PdfSigningRequest(
            placeholder.CreateContentToSign(),
            options.DigestAlgorithm,
            options.Filter,
            options.SubFilter,
            options.Metadata,
            options.ReservedContentsLength);
        var cmsSignature = (await signatureProvider.SignAsync(request, cancellationToken).ConfigureAwait(false)).ToArray();

        if (options.AddTimestamp)
        {
            var timestampedSignature = await signatureProvider.TimestampAsync(
                new PdfTimestampRequest(
                    cmsSignature,
                    options.DigestAlgorithm,
                    options.Filter,
                    options.SubFilter,
                    options.Metadata),
                cancellationToken).ConfigureAwait(false);

            if (timestampedSignature.HasValue)
            {
                cmsSignature = timestampedSignature.Value.ToArray();
            }
        }

        placeholder.PatchContents(cmsSignature);

        if (output.CanSeek)
        {
            output.Seek(0, SeekOrigin.End);
        }
    }

    private static void ValidateOptions(PdfDocument document, PdfSignatureOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.FieldName))
        {
            throw new ArgumentException("A non-empty signature field name must be provided.", nameof(options));
        }

        if (options.ReservedContentsLength <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The reserved contents length must be greater than zero.");
        }

        if (string.IsNullOrWhiteSpace(options.Filter))
        {
            throw new ArgumentException("A non-empty signature filter name must be provided.", nameof(options));
        }

        if (string.IsNullOrWhiteSpace(options.SubFilter))
        {
            throw new ArgumentException("A non-empty signature subfilter name must be provided.", nameof(options));
        }

        if (string.IsNullOrWhiteSpace(options.DigestAlgorithm))
        {
            throw new ArgumentException("A non-empty digest algorithm name must be provided.", nameof(options));
        }

        if (options.Placement != null && (options.Placement.PageNumber <= 0 || options.Placement.PageNumber > document.NumberOfPages))
        {
            throw new ArgumentOutOfRangeException(nameof(options), $"The signature placement page number must be between 1 and {document.NumberOfPages}.");
        }

        if (document.TryGetForm(out var form) && form.TryGetField(options.FieldName, out _))
        {
            throw new InvalidOperationException($"A form field named '{options.FieldName}' already exists in the source document.");
        }
    }

    private sealed class IncrementalSigningSession
    {
        private readonly PdfDocument document;
        private readonly Stream output;
        private readonly PdfSignatureOptions options;
        private readonly Dictionary<IndirectReference, long> offsets = [];
        private int nextObjectNumber;

        public IncrementalSigningSession(
            PdfDocument document,
            Stream output,
            PdfSignatureOptions options)
        {
            this.document = document;
            this.output = output;
            this.options = options;

            nextObjectNumber = document.signingContext.MaxObjectNumber + 1;
        }

        public SignaturePlaceholder WriteRevision()
        {
            var placement = options.Placement ?? PdfSignatureFieldPlacement.Default;
            var pageNode = document.Structure.Catalog.Pages.GetPageNode(placement.PageNumber);
            var pageReference = pageNode.Reference;

            var signatureReference = ReserveReference();
            var fieldReference = ReserveReference();

            IndirectReference acroFormReference;
            DictionaryToken acroFormDictionary;

            bool writeCatalogUpdate;

            if (document.TryGetForm(out var existingForm))
            {
                acroFormReference = existingForm.Reference ?? ReserveReference();
                acroFormDictionary = CloneDictionary(existingForm.Dictionary);
                writeCatalogUpdate = existingForm.Reference == null;
            }
            else
            {
                acroFormReference = ReserveReference();
                acroFormDictionary = new DictionaryToken(new Dictionary<NameToken, IToken>());
                writeCatalogUpdate = true;
            }

            var placeholder = WriteSignatureDictionary(signatureReference);
            WriteFieldDictionary(fieldReference, signatureReference, pageReference, placement.Bounds);
            WritePageUpdate(pageNode, fieldReference);
            WriteAcroFormUpdate(acroFormReference, acroFormDictionary, fieldReference);

            if (writeCatalogUpdate)
            {
                WriteCatalogUpdate(acroFormReference);
            }

            WriteCrossReferenceAndTrailer();
            return placeholder;
        }

        private IndirectReference ReserveReference() => new(nextObjectNumber++, 0);

        private SignaturePlaceholder WriteSignatureDictionary(IndirectReference signatureReference)
        {
            offsets[signatureReference] = output.Position;

            WriteAscii($"{signatureReference.ObjectNumber} {signatureReference.Generation} obj\n<<\n");
            WriteNameEntry(NameToken.Type, NameToken.Sig);
            WriteNameEntry(NameToken.Filter, NameToken.Create(options.Filter));
            WriteNameEntry(NameToken.SubFilter, NameToken.Create(options.SubFilter));
            WriteStringEntry(NameToken.M, FormatPdfDate(DateTimeOffset.UtcNow));

            WriteOptionalStringEntry(NameToken.Reason, options.Metadata.Reason);
            WriteOptionalStringEntry(NameToken.Location, options.Metadata.Location);
            WriteOptionalStringEntry(NameToken.ContactInfo, options.Metadata.ContactInfo);
            WriteOptionalStringEntry(NameToken.Name, options.Metadata.Name);

            WriteChar('/');
            WriteAscii(NameToken.Byterange.Data);
            WriteChar(' ');
            var byteRangeStart = output.Position;
            var byteRangePlaceholder = BuildByteRangePlaceholder();
            WriteAscii(byteRangePlaceholder);
            var byteRangeLength = output.Position - byteRangeStart;
            WriteAscii("\n/");
            WriteAscii(NameToken.Contents.Data);
            WriteChar(' ');
            var contentsStart = output.Position;
            WriteChar('<');
            var contentsHexStart = output.Position;
            WriteAscii(new string('0', options.ReservedContentsLength * 2));
            var contentsHexLength = output.Position - contentsHexStart;
            WriteChar('>');
            var contentsEnd = output.Position;
            WriteAscii("\n>>\nendobj\n");

            return new SignaturePlaceholder(
                output,
                byteRangeStart,
                byteRangeLength,
                contentsStart,
                contentsHexStart,
                contentsHexLength,
                contentsEnd,
                options.ReservedContentsLength);
        }

        private void WriteFieldDictionary(
            IndirectReference fieldReference,
            IndirectReference signatureReference,
            IndirectReference pageReference,
            PdfRectangle bounds)
        {
            var dictionary = new Dictionary<NameToken, IToken>
            {
                [NameToken.Type] = NameToken.Annot,
                [NameToken.Subtype] = NameToken.Widget,
                [NameToken.Ft] = NameToken.Sig,
                [NameToken.T] = new StringToken(options.FieldName),
                [NameToken.V] = new IndirectReferenceToken(signatureReference),
                [NameToken.P] = new IndirectReferenceToken(pageReference),
                [NameToken.Rect] = new ArrayToken([
                    new NumericToken(bounds.Left),
                    new NumericToken(bounds.Bottom),
                    new NumericToken(bounds.Right),
                    new NumericToken(bounds.Top)
                ]),
                [NameToken.F] = new NumericToken(4)
            };

            WriteToken(fieldReference, dictionary);
        }

        private void WritePageUpdate(PageTreeNode pageNode, IndirectReference fieldReference)
        {
            var dictionary = CloneDictionaryData(pageNode.NodeDictionary);
            var annotations = ResolveArrayToken(dictionary, NameToken.Annots);

            var updatedAnnotations = new List<IToken>(annotations?.Data ?? [])
            {
                new IndirectReferenceToken(fieldReference)
            };

            dictionary[NameToken.Annots] = new ArrayToken(updatedAnnotations);
            WriteToken(pageNode.Reference, dictionary);
        }

        private void WriteAcroFormUpdate(
            IndirectReference acroFormReference,
            DictionaryToken sourceAcroFormDictionary,
            IndirectReference fieldReference)
        {
            var dictionary = CloneDictionaryData(sourceAcroFormDictionary);
            var fields = ResolveArrayToken(dictionary, NameToken.Fields);
            var updatedFields = new List<IToken>(fields?.Data ?? [])
            {
                new IndirectReferenceToken(fieldReference)
            };

            dictionary[NameToken.Fields] = new ArrayToken(updatedFields);

            var signatureFlags = SignatureFlags.SignaturesExist | SignatureFlags.AppendOnly;
            if (document.TryGetForm(out var existingForm))
            {
                signatureFlags |= existingForm.SignatureFlags;
            }

            dictionary[NameToken.SigFlags] = new NumericToken((int)signatureFlags);
            WriteToken(acroFormReference, new DictionaryToken(dictionary));
        }

        private void WriteCatalogUpdate(IndirectReference acroFormReference)
        {
            var dictionary = CloneDictionaryData(document.Structure.Catalog.CatalogDictionary);
            dictionary[NameToken.AcroForm] = new IndirectReferenceToken(acroFormReference);
            WriteToken(document.signingContext.RootReference, new DictionaryToken(dictionary));
        }

        private void WriteCrossReferenceAndTrailer()
        {
            var context = document.signingContext;

            var startXref = output.Position;
            WriteAscii("xref\n");

            foreach (var group in offsets
                         .GroupBy(x => x.Key.ObjectNumber)
                         .OrderBy(g => g.Key))
            {
                WriteAscii(group.Key);
                WriteChar(' ');
                WriteAscii(group.Count());
                WriteChar('\n');

                foreach (var item in group)
                {
                    WriteAscii(item.Value, "D10");
                    WriteAscii(" 00000 n \n");
                }
            }

            WriteAscii("trailer\n");
            WriteAscii("<<\n/");
            WriteAscii(NameToken.Size.Data);
            WriteChar(' ');
            WriteAscii(Math.Max(context.MaxObjectNumber, offsets.Keys.Max(x => x.ObjectNumber)) + 1);
            WriteAscii("\n/");
            WriteAscii(NameToken.Root.Data);
            WriteChar(' ');
            TokenWriter.Instance.WriteToken(new IndirectReferenceToken(context.RootReference), output);

            if (context.InformationReference.HasValue)
            {
                WriteChar('/');
                WriteAscii(NameToken.Info.Data);
                WriteChar(' ');
                TokenWriter.Instance.WriteToken(new IndirectReferenceToken(context.InformationReference.Value), output);
            }

            if (context.FileIdentifier.Count > 0)
            {
                WriteChar('/');
                WriteAscii(NameToken.Id.Data);
                WriteChar(' ');
                TokenWriter.Instance.WriteToken(new ArrayToken(context.FileIdentifier.Select(CloneToken).ToList()), output);
            }

            WriteChar('/');
            WriteAscii(NameToken.Prev.Data);
            WriteChar(' ');
            WriteAscii(context.PreviousCrossReferenceOffset);
            WriteAscii("\n>>\nstartxref\n");
            WriteAscii(startXref.ToString(CultureInfo.InvariantCulture));
            WriteAscii("\n%%EOF\n");
        }

        private void WriteToken(IndirectReference reference, IReadOnlyDictionary<NameToken, IToken> data) =>
            WriteToken(reference, new DictionaryToken(data));

        private void WriteToken(IndirectReference reference, IToken token)
        {
            offsets[reference] = output.Position;
            TokenWriter.Instance.WriteToken(new ObjectToken(XrefLocation.File(output.Position), reference, token), output);
        }

        private void WriteNameEntry(NameToken key, NameToken value)
        {
            WriteChar('/');
            WriteAscii(key.Data);
            WriteChar(' ');
            TokenWriter.Instance.WriteToken(value, output);
        }

        private void WriteOptionalStringEntry(NameToken key, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                WriteStringEntry(key, value);
            }
        }

        private void WriteStringEntry(NameToken key, string value)
        {
            WriteChar('/');
            WriteAscii(key.Data);
            WriteChar(' ');
            TokenWriter.Instance.WriteToken(new StringToken(value), output);
        }

        private void WriteAscii(string value)
        {
            var bytes = Encoding.ASCII.GetBytes(value);
            output.Write(bytes, 0, bytes.Length);
        }

        private void WriteAscii(IFormattable value, string? format = null) =>
            WriteAscii(value.ToString(format, CultureInfo.InvariantCulture));

        private void WriteChar(char value)
        {
            output.WriteByte((byte)value);
        }

        private ArrayToken? ResolveArrayToken(Dictionary<NameToken,IToken> dictionary, NameToken key) =>
            dictionary.TryGetValue(key, out var token)
                ? document.Advanced.FindDirectObject<ArrayToken>(token)
                : null;

        private static string BuildByteRangePlaceholder()
        {
            var placeholder = new string('0', ByteRangeNumberWidth);
            return $"[{placeholder} {placeholder} {placeholder} {placeholder}]";
        }
    }

    private sealed class SignaturePlaceholder
    {
        private readonly Stream output;
        private readonly long byteRangeStart;
        private readonly long byteRangeLength;
        private readonly long contentsStart;
        private readonly long contentsHexStart;
        private readonly long contentsHexLength;
        private readonly long contentsEnd;
        private readonly int reservedContentsLength;

        public SignaturePlaceholder(
            Stream output,
            long byteRangeStart,
            long byteRangeLength,
            long contentsStart,
            long contentsHexStart,
            long contentsHexLength,
            long contentsEnd,
            int reservedContentsLength)
        {
            this.output = output;
            this.byteRangeStart = byteRangeStart;
            this.byteRangeLength = byteRangeLength;
            this.contentsStart = contentsStart;
            this.contentsHexStart = contentsHexStart;
            this.contentsHexLength = contentsHexLength;
            this.contentsEnd = contentsEnd;
            this.reservedContentsLength = reservedContentsLength;
        }

        public void PatchByteRange()
        {
            var length2 = output.Length - contentsEnd;
            var value = string.Format(
                CultureInfo.InvariantCulture,
                "[{0:D20} {1:D20} {2:D20} {3:D20}]",
                0,
                contentsStart,
                contentsEnd,
                length2);

            if (value.Length != byteRangeLength)
            {
                throw new InvalidOperationException("The computed /ByteRange value does not fit in the reserved placeholder.");
            }

            WriteAt(byteRangeStart, Encoding.ASCII.GetBytes(value));
        }

        public byte[] CreateContentToSign()
        {
            if (!output.CanSeek)
            {
                throw new InvalidOperationException("The output stream must support seeking while the signature placeholder is being patched.");
            }

            var length1 = (int)contentsStart;
            var length2 = (int)(output.Length - contentsEnd);

            var snapshot = new byte[length1 + length2];

            var originalPosition = output.Position;

            var read = 0;

            // Read length1 bytes at start of stream
            output.Seek(0, SeekOrigin.Begin);
            while (read < length1)
            {
                var bytesRead = output.Read(snapshot, read, length1 - read);
                if (bytesRead == 0)
                {
                    throw new EndOfStreamException("Unable to read the first /ByteRange segment from the output stream.");
                }
                read += bytesRead;
            }

            // Read length2 bytes starting from contentsEnd
            output.Seek(contentsEnd, SeekOrigin.Begin);
            read = 0;
            while (read < length2)
            {
                var bytesRead = output.Read(snapshot, length1 + read, length2 - read);
                if (bytesRead == 0)
                {
                    throw new EndOfStreamException("Unable to read the second /ByteRange segment from the output stream.");
                }
                read += bytesRead;
            }

            output.Seek(originalPosition, SeekOrigin.Begin);

            return snapshot;
        }

        public void PatchContents(ReadOnlySpan<byte> cmsSignature)
        {
            if (cmsSignature.Length > reservedContentsLength)
            {
                throw new InvalidOperationException($"The generated CMS signature requires {cmsSignature.Length} bytes but only {reservedContentsLength} were reserved.");
            }

            var hex = ConvertToHex(cmsSignature, reservedContentsLength);
            if (hex.Length != contentsHexLength)
            {
                throw new InvalidOperationException("The generated CMS signature does not fit the reserved /Contents hex placeholder.");
            }

            WriteAt(contentsHexStart, hex);
        }

        private void WriteAt(long position, byte[] data)
        {
            var originalPosition = output.Position;
            output.Seek(position, SeekOrigin.Begin);
            output.Write(data, 0, data.Length);
            output.Seek(originalPosition, SeekOrigin.Begin);
        }

        private static byte[] ConvertToHex(ReadOnlySpan<byte> data, int reservedContentsLength)
        {
            var bytes = new byte[reservedContentsLength * 2];
            var index = 0;

            foreach (var value in data)
            {
                bytes[index++] = GetHexCharacter(value >> 4);
                bytes[index++] = GetHexCharacter(value & 0x0F);
            }

            while (index < bytes.Length)
            {
                bytes[index++] = (byte)'0';
            }

            return bytes;

            static byte GetHexCharacter(int value)
            {
                value = value < 10
                    ? '0' + value
                    : 'A' + (value - 10);
                return (byte)value;
            }
        }
    }

    private static Dictionary<NameToken, IToken> CloneDictionaryData(DictionaryToken dictionary) =>
        dictionary.Data.ToDictionary(
            x => NameToken.Create(x.Key),
            x => CloneToken(x.Value));

    private static DictionaryToken CloneDictionary(DictionaryToken dictionary) =>
        new(CloneDictionaryData(dictionary));

    private static IToken CloneToken(IToken token) => token switch
    {
        DictionaryToken dictionaryToken => CloneDictionary(dictionaryToken),
        ArrayToken arrayToken => new ArrayToken(arrayToken.Data.Select(CloneToken).ToList()),
        StreamToken streamToken =>
            new StreamToken(CloneDictionary(streamToken.StreamDictionary), streamToken.Data.ToArray()),
        StringToken stringToken => new StringToken(stringToken.Data, stringToken.EncodedWith),
        NumericToken numericToken => new NumericToken(numericToken.Data),
        IndirectReferenceToken referenceToken => new IndirectReferenceToken(referenceToken.Data),
        _ => token
    };

    private static string FormatPdfDate(DateTimeOffset dateTimeOffset)
    {
        var offset = dateTimeOffset.Offset;
        if (offset == TimeSpan.Zero)
        {
            return $"D:{dateTimeOffset:yyyyMMddHHmmss}Z";
        }

        var sign = offset < TimeSpan.Zero ? '-' : '+';
        offset = offset.Duration();
        return $"D:{dateTimeOffset:yyyyMMddHHmmss}{sign}{offset.Hours:00}'{offset.Minutes:00}'";
    }
}