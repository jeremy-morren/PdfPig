namespace UglyToad.PdfPig.AcroForms.Fields
{
    using Core;

    /// <summary>
    /// Information from the field dictionary which is common across all field types.
    /// All of this information is optional.
    /// </summary>
    public class AcroFieldCommonInformation
    {
        /// <summary>
        /// The indirect reference for this field, if it was defined as an indirect object.
        /// </summary>
        public IndirectReference? Reference { get; }

        /// <summary>
        /// The reference to the field which is the parent of this one, if applicable.
        /// </summary>
        public IndirectReference? Parent { get; set; }

        /// <summary>
        /// The fully qualified field name built from the partial names of all ancestor fields and this field.
        /// </summary>
        public string? FullyQualifiedName { get; }

        /// <summary>
        /// The partial field name for this field. The fully qualified field name is the
        /// period '.' joined name of all parents' partial names and this field's partial name.
        /// </summary>
        public string? PartialName { get; }

        /// <summary>
        /// The alternate field name to be used instead of the fully qualified field name where
        /// the field is being identified on the user interface or by screen readers.
        /// </summary>
        public string? AlternateName { get; }

        /// <summary>
        /// The mapping name used when exporting form field data from the document.
        /// </summary>
        public string? MappingName { get; }

        /// <summary>
        /// Create a new <see cref="AcroFieldCommonInformation"/>.
        /// </summary>
        /// <param name="reference">The field reference, if any.</param>
        /// <param name="parent">The parent field reference, if any.</param>
        /// <param name="fullyQualifiedName">The fully qualified field name, if known.</param>
        /// <param name="partialName">The partial field name for this field, if any.</param>
        /// <param name="alternateName">The alternate field name, if any.</param>
        /// <param name="mappingName">The export mapping name, if any.</param>
        public AcroFieldCommonInformation(IndirectReference? parent, string? fullyQualifiedName, string? partialName, string? alternateName, string? mappingName, IndirectReference? reference = null)
        {
            Reference = reference;
            Parent = parent;
            FullyQualifiedName = fullyQualifiedName;
            PartialName = partialName;
            AlternateName = alternateName;
            MappingName = mappingName;
        }

        /// <inheritdoc />
        public override string ToString()
        {
            string AppendIfNotNull(string? val, string label, string result)
            {
                if (val is null)
                {
                    return result;
                }

                if (result.Length > 0)
                {
                    result += " ";
                }

                result += $"{label}: {val}.";

                return result;
            }

            var s = string.Empty;

            if (Reference != null)
            {
                s += $"Reference: {Reference}.";
            }
            
            if (Parent != null)
            {
                if (s.Length > 0)
                {
                    s += " ";
                }

                s += $"Parent: {Parent}.";
            }

            s = AppendIfNotNull(FullyQualifiedName, "Fully Qualified Name", s);
            s = AppendIfNotNull(PartialName, "Partial Name", s);
            s = AppendIfNotNull(AlternateName, "Alternate Name", s);
            s = AppendIfNotNull(MappingName, "Mapping Name", s);

            return s;
        }
    }
}