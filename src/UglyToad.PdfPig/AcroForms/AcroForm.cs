namespace UglyToad.PdfPig.AcroForms
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Core;
    using Fields;
    using System.Diagnostics.CodeAnalysis;
    using Tokens;

    /// <summary>
    /// A collection of interactive fields for gathering data from a user through dropdowns, textboxes, checkboxes, etc.
    /// Each <see cref="PdfDocument"/> with form functionality contains a single <see cref="AcroForm"/> spread across one or more pages.
    /// </summary>
    /// <remarks>
    /// The name AcroForm distinguishes this from the other form type called form XObjects which act as templates for repeated sections of content.
    /// </remarks>
    public class AcroForm
    {
        private readonly IReadOnlyDictionary<IndirectReference, AcroFieldBase> fieldsWithReferences;

        /// <summary>
        /// The raw PDF dictionary which is the root form object.
        /// </summary>
        public DictionaryToken Dictionary { get; }

        /// <summary>
        /// The indirect reference for the root AcroForm object, if it was defined as an indirect object.
        /// </summary>
        public IndirectReference? Reference { get; }

        /// <summary>
        /// Document-level characteristics related to signature fields.
        /// </summary>
        public SignatureFlags SignatureFlags { get; }

        /// <summary>
        /// Whether all widget annotations need appearance dictionaries and streams.
        /// </summary>
        public bool NeedAppearances { get; }

        /// <summary>
        /// All root fields in this form.
        /// </summary>
        public IReadOnlyList<AcroFieldBase> Fields { get; }

        /// <summary>
        /// Create a new <see cref="AcroForm"/>.
        /// </summary>
        internal AcroForm(DictionaryToken dictionary, SignatureFlags signatureFlags, bool needAppearances,
            IReadOnlyDictionary<IndirectReference, AcroFieldBase> fieldsWithReferences,
            IndirectReference? reference = null)
        {
            Dictionary = dictionary ?? throw new ArgumentNullException(nameof(dictionary));
            Reference = reference;
            SignatureFlags = signatureFlags;
            NeedAppearances = needAppearances;
            this.fieldsWithReferences = fieldsWithReferences ?? throw new ArgumentNullException(nameof(fieldsWithReferences));
            Fields = fieldsWithReferences.Values.ToList();
        }

        /// <summary>
        /// Attempt to get a form field by its indirect reference.
        /// </summary>
        public bool TryGetField(IndirectReference reference, [NotNullWhen(true)] out AcroFieldBase? field)
        {
            if (fieldsWithReferences.TryGetValue(reference, out field))
            {
                return true;
            }

            field = EnumerateFields(Fields).FirstOrDefault(x => x.Information.Reference == reference);
            return field != null;
        }

        /// <summary>
        /// Attempt to get a form field by its fully qualified field name.
        /// </summary>
        public bool TryGetField(string fullyQualifiedName, [NotNullWhen(true)] out AcroFieldBase? field)
        {
            if (string.IsNullOrWhiteSpace(fullyQualifiedName))
            {
                throw new ArgumentException("A fully qualified field name must be provided.", nameof(fullyQualifiedName));
            }

            field = EnumerateFields(Fields).FirstOrDefault(x => string.Equals(x.Information.FullyQualifiedName, fullyQualifiedName, StringComparison.Ordinal));
            return field != null;
        }

        /// <summary>
        /// Get the set of fields which appear on the given page number.
        /// </summary>
        public IEnumerable<AcroFieldBase> GetFieldsForPage(int pageNumber)
        {
            if (pageNumber <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(pageNumber), $"Page number starts at 1, instead got {pageNumber}.");
            }

            foreach (var field in Fields)
            {
                if (field.PageNumber == pageNumber)
                {
                    yield return field;
                }
                else if (field is AcroNonTerminalField parent
                && parent.Children.Any(x => x.PageNumber == pageNumber))
                {
                    yield return field;
                }
            }
        }

        /// <inheritdoc />
        public override string ToString()
        {
            return Dictionary.ToString();
        }

        private static IEnumerable<AcroFieldBase> EnumerateFields(IEnumerable<AcroFieldBase> fields)
        {
            foreach (var field in fields)
            {
                yield return field;

                if (field is AcroNonTerminalField parent)
                {
                    foreach (var child in EnumerateFields(parent.Children))
                    {
                        yield return child;
                    }
                }
            }
        }
    }
}

