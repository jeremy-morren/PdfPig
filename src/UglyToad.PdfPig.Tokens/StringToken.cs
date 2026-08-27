namespace UglyToad.PdfPig.Tokens
{
    using System;
    using Core;

    /// <summary>
    /// Represents a string of text contained in a PDF document.
    /// </summary>
    public class StringToken : IDataToken<string>
    {
        /// <summary>
        /// The string in the token.
        /// </summary>
        public string Data { get; }

        /// <summary>
        /// The encoding used to generate the <see langword="string"/> in <see cref="Data"/>
        /// from the bytes in the file.
        /// </summary>
        public Encoding EncodedWith { get; }

        /// <summary>
        /// The length of the token as serialized in the PDF source, including the surrounding parentheses.
        /// </summary>
        public int SerializedLength { get; }

        /// <summary>
        /// Create a new <see cref="StringToken"/>.
        /// </summary>
        /// <param name="data">The string data for the token to contain.</param>
        /// <param name="encodedWith">The encoding used to generate the <see cref="Data"/>.</param>
        public StringToken(string data, Encoding encodedWith = Encoding.Iso88591)
            : this(data, encodedWith, GetCanonicalSerializedLength(data, encodedWith))
        {
        }

        /// <summary>
        /// Create a new <see cref="StringToken"/>.
        /// </summary>
        /// <param name="data">The string data for the token to contain.</param>
        /// <param name="encodedWith">The encoding used to generate the <see cref="Data"/>.</param>
        /// <param name="serializedLength">The length of the token as serialized in the source PDF, including delimiters.</param>
        public StringToken(string data, Encoding encodedWith, int serializedLength)
        {
            Data = data ?? throw new ArgumentNullException(nameof(data));
            EncodedWith = encodedWith;

            if (serializedLength < 2)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(serializedLength),
                    "Serialized length must include the surrounding parentheses.");
            }
            SerializedLength = serializedLength;
        }

        /// <summary>
        /// Convert the <see langword="string"/> in <see cref="Data"/> back to bytes.
        /// </summary>
        public byte[] GetBytes() => GetBytes(Data, EncodedWith);

        private static byte[] GetBytes(string data, Encoding encodedWith)
        {
            switch (encodedWith)
            {
                case Encoding.Utf16BE:
                {
                    var bytes = System.Text.Encoding.BigEndianUnicode.GetBytes(data);

                    var result = new byte[bytes.Length + 2];
                    result[0] = 0xFE;
                    result[1] = 0xFF;

                    Array.Copy(bytes, 0, result, 2, bytes.Length);

                    return result;
                }
                case Encoding.Utf16:
                {
                    return System.Text.Encoding.Unicode.GetBytes(data);
                }
                case Encoding.PdfDocEncoding:
                    return PdfDocEncoding.StringToBytes(data);
                default:
                    return OtherEncodings.StringAsLatin1Bytes(data);
            }
        }

        /// <inheritdoc />
        public bool Equals(IToken obj)
        {
            if (ReferenceEquals(this, obj))
            {
                return true;
            }

            if (!(obj is StringToken other))
            {
                return false;
            }

            return EncodedWith.Equals(other.EncodedWith) && Data.Equals(other.Data);
        }

        /// <inheritdoc />
        public override string ToString()
        {
            return $"({Data})";
        }

        /// <summary>
        /// The encoding used to convert the underlying file bytes to the string.
        /// </summary>
        public enum Encoding : byte
        {
            /// <summary>
            /// <see cref="OtherEncodings.Iso88591"/>.
            /// </summary>
            Iso88591 = 0,
            /// <summary>
            /// UTF-16.
            /// </summary>
            Utf16 = 1,
            /// <summary>
            /// UTF-16 Big Endian.
            /// </summary>
            Utf16BE = 2,
            /// <summary>
            /// The PdfDocEncoding for strings in the body of a PDF file.
            /// </summary>
            PdfDocEncoding = 3,
        }

        private static int GetCanonicalSerializedLength(string data, Encoding encodedWith)
        {
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (encodedWith is Encoding.Utf16 or Encoding.Utf16BE)
            {
                return GetBytes(data, encodedWith).Length + 2;
            }

            var length = 2;

            foreach (var c in data)
            {
                if (c is '(' or ')' or '\\' or '\n' or '\r' or '\t' or '\b' or '\f')
                {
                    length += 2;
                }
                else if (c < 32 || c > 126)
                {
                    length += 4;
                }
                else
                {
                    length += 1;
                }
            }

            return length;
        }
    }
}