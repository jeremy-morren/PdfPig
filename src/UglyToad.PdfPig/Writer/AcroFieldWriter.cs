namespace UglyToad.PdfPig.Writer;

using AcroForms;
using AcroForms.Fields;
using Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Tokens;

/// <summary>
/// Adds AcroForm fields to an existing PDF document and writes the updated document to a new stream.
/// </summary>
public sealed partial class AcroFieldWriter
{
    private static readonly NameToken WidgetName = NameToken.Create("Widget");
    private static readonly NameToken AnnotName = NameToken.Create("Annot");
    private static readonly NameToken YesName = NameToken.Create("Yes");

    private readonly PdfDocument sourceDocument;
    private readonly List<FieldDefinition> fields = [];

    /// <summary>
    /// Create a new <see cref="AcroFieldWriter"/> for the provided source document.
    /// </summary>
    public AcroFieldWriter(PdfDocument sourceDocument)
    {
        this.sourceDocument = sourceDocument ?? throw new ArgumentNullException(nameof(sourceDocument));
    }

    /// <summary>
    /// Gets the fields added to this writer
    /// </summary>
    public IReadOnlyList<FieldDefinition> GetFields() => fields.AsReadOnly();

    /// <summary>
    /// Adds a text field to the in-memory changeset.
    /// </summary>
    /// <param name="pageNumber">The 1-based page number on which the widget annotation should be created.</param>
    /// <param name="partialName">The partial field name to store in the field dictionary <c>/T</c> entry.</param>
    /// <param name="bounds">The widget rectangle in page user-space coordinates.</param>
    /// <param name="value">The optional initial field value to write to the field dictionary <c>/V</c> entry.</param>
    /// <param name="flags">The text-field flags to write to the field dictionary <c>/Ff</c> entry. Supported flags are <see cref="AcroTextFieldFlags.ReadOnly"/>, <see cref="AcroTextFieldFlags.Required"/>, <see cref="AcroTextFieldFlags.NoExport"/>, <see cref="AcroTextFieldFlags.Multiline"/>, <see cref="AcroTextFieldFlags.Password"/>, <see cref="AcroTextFieldFlags.FileSelect"/>, <see cref="AcroTextFieldFlags.DoNotSpellCheck"/>, <see cref="AcroTextFieldFlags.DoNotScroll"/>, <see cref="AcroTextFieldFlags.Comb"/>, and <see cref="AcroTextFieldFlags.RichText"/>.</param>
    /// <param name="maxLength">The optional maximum number of characters to write to the field dictionary <c>/MaxLen</c> entry.</param>
    public void AddTextField(
        int pageNumber,
        string partialName,
        PdfRectangle bounds,
        string? value = null,
        AcroTextFieldFlags flags = 0,
        int? maxLength = null)
    {
        ValidateFieldInput(pageNumber, partialName, bounds);
        ValidateTextFieldFlags(flags);

        fields.Add(new TextFieldDefinition(pageNumber, partialName, bounds, value, flags, maxLength));
    }

    /// <summary>
    /// Adds a checkbox field to the in-memory changeset.
    /// </summary>
    /// <param name="pageNumber">The 1-based page number on which the widget annotation should be created.</param>
    /// <param name="partialName">The partial field name to store in the field dictionary <c>/T</c> entry.</param>
    /// <param name="bounds">The widget rectangle in page user-space coordinates.</param>
    /// <param name="isChecked"><see langword="true"/> to set the field value and appearance state to the on-state name; otherwise <see langword="false"/> to use <c>/Off</c>.</param>
    /// <param name="onStateName">The export value and appearance state name to use when the checkbox is on. A blank value or <c>Off</c> is normalized to <c>Yes</c>.</param>
    /// <param name="flags">The button-field flags to write to the field dictionary <c>/Ff</c> entry. Supported flags are <see cref="AcroButtonFieldFlags.ReadOnly"/>, <see cref="AcroButtonFieldFlags.Required"/>, and <see cref="AcroButtonFieldFlags.NoExport"/>.</param>
    public void AddCheckboxField(
        int pageNumber,
        string partialName,
        PdfRectangle bounds,
        bool isChecked,
        string onStateName = "Yes",
        AcroButtonFieldFlags flags = 0)
    {
        ValidateFieldInput(pageNumber, partialName, bounds);
        ValidateCheckboxFieldFlags(flags);
        fields.Add(new CheckboxFieldDefinition(pageNumber, partialName, bounds, isChecked, GetStateName(onStateName), flags));
    }

    /// <summary>
    /// Adds a group of related checkboxes to the in-memory changeset.
    /// </summary>
    /// <param name="pageNumber">The 1-based page number on which the checkbox widgets should be created.</param>
    /// <param name="partialName">The partial field name to store in the parent field dictionary <c>/T</c> entry.</param>
    /// <param name="checkboxes">The widget definitions for the group, where each item provides the widget rectangle, the on-state/export value, and whether that widget starts checked.</param>
    /// <param name="flags">The shared button-field flags to write to the parent field dictionary <c>/Ff</c> entry. Supported flags are <see cref="AcroButtonFieldFlags.ReadOnly"/>, <see cref="AcroButtonFieldFlags.Required"/>, and <see cref="AcroButtonFieldFlags.NoExport"/>.</param>
    public void AddCheckboxesField(
        int pageNumber,
        string partialName,
        IReadOnlyList<(PdfRectangle Bounds, string StateName, bool IsChecked)> checkboxes,
        AcroButtonFieldFlags flags = 0)
    {
        ValidateWidgetItems(
            pageNumber,
            partialName,
            checkboxes.Select(x => x.Bounds).ToList(),
            nameof(checkboxes));
        ValidateCheckboxFieldFlags(flags);
        fields.Add(new CheckboxesFieldDefinition(
            pageNumber,
            partialName,
            checkboxes.Select(x => new WidgetItem(x.Bounds, GetStateName(x.StateName), x.IsChecked)).ToList(),
            flags));
    }

    /// <summary>
    /// Adds a single radio button field to the in-memory changeset.
    /// </summary>
    /// <param name="pageNumber">The 1-based page number on which the widget annotation should be created.</param>
    /// <param name="partialName">The partial field name to store in the field dictionary <c>/T</c> entry.</param>
    /// <param name="bounds">The widget rectangle in page user-space coordinates.</param>
    /// <param name="isSelected"><see langword="true"/> to set the field value and appearance state to the supplied state name; otherwise <see langword="false"/> to use <c>/Off</c>.</param>
    /// <param name="stateName">The export value and appearance state name for the selected radio button. A blank value or <c>Off</c> is normalized to <c>Yes</c>.</param>
    /// <param name="flags">Additional button-field flags to combine with the required radio-button <c>/Ff</c> flag bits. Supported flags are <see cref="AcroButtonFieldFlags.ReadOnly"/>, <see cref="AcroButtonFieldFlags.Required"/>, <see cref="AcroButtonFieldFlags.NoExport"/>, <see cref="AcroButtonFieldFlags.NoToggleToOff"/>, and <see cref="AcroButtonFieldFlags.RadiosInUnison"/>.</param>
    public void AddRadioButtonField(
        int pageNumber,
        string partialName,
        PdfRectangle bounds,
        bool isSelected,
        string stateName = "Yes",
        AcroButtonFieldFlags flags = 0)
    {
        ValidateFieldInput(pageNumber, partialName, bounds);
        ValidateRadioFieldFlags(flags);
        fields.Add(new RadioButtonFieldDefinition(pageNumber, partialName, bounds, isSelected, GetStateName(stateName), flags | AcroButtonFieldFlags.Radio));
    }

    /// <summary>
    /// Adds a group of radio buttons to the in-memory changeset.
    /// </summary>
    /// <param name="pageNumber">The 1-based page number on which the radio button widgets should be created.</param>
    /// <param name="partialName">The partial field name to store in the parent field dictionary <c>/T</c> entry.</param>
    /// <param name="radioButtons">The widget definitions for the group, where each item provides the widget rectangle, the state name/export value, and whether that widget starts selected.</param>
    /// <param name="flags">Additional button-field flags to combine with the required radio-button <c>/Ff</c> flag bits on the parent field. Supported flags are <see cref="AcroButtonFieldFlags.ReadOnly"/>, <see cref="AcroButtonFieldFlags.Required"/>, <see cref="AcroButtonFieldFlags.NoExport"/>, <see cref="AcroButtonFieldFlags.NoToggleToOff"/>, and <see cref="AcroButtonFieldFlags.RadiosInUnison"/>.</param>
    public void AddRadioButtonsField(int pageNumber, string partialName,
        IReadOnlyList<(PdfRectangle Bounds, string StateName, bool IsSelected)> radioButtons,
        AcroButtonFieldFlags flags = 0)
    {
        ValidateWidgetItems(pageNumber, partialName, radioButtons.Select(x => x.Bounds).ToArray(), nameof(radioButtons));
        ValidateRadioFieldFlags(flags);
        fields.Add(new RadioButtonsFieldDefinition(pageNumber, partialName,
            radioButtons.Select(x => new WidgetItem(x.Bounds, GetStateName(x.StateName), x.IsSelected)).ToArray(),
            flags | AcroButtonFieldFlags.Radio));
    }

    /// <summary>
    /// Adds a push button field to the in-memory changeset.
    /// </summary>
    /// <param name="pageNumber">The 1-based page number on which the widget annotation should be created.</param>
    /// <param name="partialName">The partial field name to store in the field dictionary <c>/T</c> entry.</param>
    /// <param name="bounds">The widget rectangle in page user-space coordinates.</param>
    /// <param name="flags">Additional button-field flags to combine with the required push-button <c>/Ff</c> flag bit. Supported flags are <see cref="AcroButtonFieldFlags.ReadOnly"/>, <see cref="AcroButtonFieldFlags.Required"/>, and <see cref="AcroButtonFieldFlags.NoExport"/>.</param>
    public void AddPushButtonField(int pageNumber, string partialName, PdfRectangle bounds, AcroButtonFieldFlags flags = 0)
    {
        ValidateFieldInput(pageNumber, partialName, bounds);
        ValidatePushButtonFieldFlags(flags);
        fields.Add(new PushButtonFieldDefinition(pageNumber, partialName, bounds, flags | AcroButtonFieldFlags.PushButton));
    }

    /// <summary>
    /// Adds a combo box field to the in-memory changeset.
    /// </summary>
    /// <param name="pageNumber">The 1-based page number on which the widget annotation should be created.</param>
    /// <param name="partialName">The partial field name to store in the field dictionary <c>/T</c> entry.</param>
    /// <param name="bounds">The widget rectangle in page user-space coordinates.</param>
    /// <param name="options">The option strings to write to the choice field <c>/Opt</c> array.</param>
    /// <param name="selectedOption">The optional initially selected option to write to the field dictionary <c>/V</c> entry.</param>
    /// <param name="flags">Additional choice-field flags to combine with the required combo-box <c>/Ff</c> flag bit. Supported flags are <see cref="AcroChoiceFieldFlags.ReadOnly"/>, <see cref="AcroChoiceFieldFlags.Required"/>, <see cref="AcroChoiceFieldFlags.NoExport"/>, <see cref="AcroChoiceFieldFlags.Edit"/>, <see cref="AcroChoiceFieldFlags.Sort"/>, <see cref="AcroChoiceFieldFlags.DoNotSpellCheck"/>, and <see cref="AcroChoiceFieldFlags.CommitOnSelectionChange"/>.</param>
    public void AddComboBoxField(int pageNumber, string partialName, PdfRectangle bounds,
        IReadOnlyList<string> options, string? selectedOption = null, AcroChoiceFieldFlags flags = 0)
    {
        ValidateChoiceFieldInput(pageNumber, partialName, bounds, options);
        ValidateComboBoxFieldFlags(flags);
        fields.Add(new ComboBoxFieldDefinition(pageNumber, partialName, bounds, options.ToArray(), selectedOption, flags | AcroChoiceFieldFlags.Combo));
    }

    /// <summary>
    /// Adds a list box field to the in-memory changeset.
    /// </summary>
    /// <param name="pageNumber">The 1-based page number on which the widget annotation should be created.</param>
    /// <param name="partialName">The partial field name to store in the field dictionary <c>/T</c> entry.</param>
    /// <param name="bounds">The widget rectangle in page user-space coordinates.</param>
    /// <param name="options">The option strings to write to the choice field <c>/Opt</c> array.</param>
    /// <param name="selectedOptions">The optional initially selected option values to write to the field dictionary <c>/V</c> entry.</param>
    /// <param name="flags">The choice-field flags to write to the field dictionary <c>/Ff</c> entry. Supported flags are <see cref="AcroChoiceFieldFlags.ReadOnly"/>, <see cref="AcroChoiceFieldFlags.Required"/>, <see cref="AcroChoiceFieldFlags.NoExport"/>, <see cref="AcroChoiceFieldFlags.Sort"/>, <see cref="AcroChoiceFieldFlags.MultiSelect"/>, and <see cref="AcroChoiceFieldFlags.CommitOnSelectionChange"/>.</param>
    /// <param name="topIndex">The optional topmost visible option index to write to the field dictionary <c>/TI</c> entry.</param>
    public void AddListBoxField(int pageNumber, string partialName, PdfRectangle bounds,
        IReadOnlyList<string> options, IReadOnlyList<string>? selectedOptions = null,
        AcroChoiceFieldFlags flags = 0, int topIndex = 0)
    {
        ValidateChoiceFieldInput(pageNumber, partialName, bounds, options);
        ValidateListBoxFieldFlags(flags);
        fields.Add(new ListBoxFieldDefinition(pageNumber, partialName, bounds, options.ToArray(), selectedOptions?.ToArray() ?? Array.Empty<string>(), flags, topIndex));
    }

    /// <summary>
    /// Adds an unsigned signature field to the in-memory changeset.
    /// </summary>
    /// <param name="pageNumber">The 1-based page number on which the widget annotation should be created.</param>
    /// <param name="partialName">The partial field name to store in the field dictionary <c>/T</c> entry.</param>
    /// <param name="bounds">The widget rectangle in page user-space coordinates.</param>
    public void AddSignatureField(int pageNumber, string partialName, PdfRectangle bounds)
    {
        ValidateFieldInput(pageNumber, partialName, bounds);
        fields.Add(new SignatureFieldDefinition(pageNumber, partialName, bounds));
    }

    /// <summary>
    /// Writes the updated document to the provided stream.
    /// </summary>
    public void Write(Stream stream)
    {
        if (stream is null)
        {
            throw new ArgumentNullException(nameof(stream));
        }

        sourceDocument.TryGetForm(out var existingForm);
        ValidateNewFieldNames(existingForm);

        using var builder = new PdfDocumentBuilder(stream, disposeStream: false, version: sourceDocument.Version);

        var pages = new Dictionary<int, PdfPageBuilder>(sourceDocument.NumberOfPages);
        for (var pageNumber = 1; pageNumber <= sourceDocument.NumberOfPages; pageNumber++)
        {
            pages[pageNumber] = builder.AddPage(sourceDocument, pageNumber, new PdfDocumentBuilder.AddPageOptions
            {
                KeepAnnotations = true
            });
        }

        if (fields.Count > 0 || existingForm != null)
        {
            WriteAcroForm(builder, pages, existingForm);
        }

        builder.Build();
    }

    /// <summary>
    /// Builds the updated document into memory and returns the written bytes.
    /// </summary>
    public byte[] Build()
    {
        using var stream = new MemoryStream();
        Write(stream);
        return stream.ToArray();
    }

    private void WriteAcroForm(PdfDocumentBuilder builder, IReadOnlyDictionary<int, PdfPageBuilder> pages, AcroForm? existingForm)
    {
        var fieldReferences = GetExistingFieldReferences(builder, existingForm);

        var writerHelper = new PdfFieldWriterHelper(builder, pages);
        foreach (var field in fields)
        {
            switch (field)
            {
                case TextFieldDefinition textField:
                    fieldReferences.Add(writerHelper.WriteTextField(textField));
                    break;
                case CheckboxFieldDefinition checkboxField:
                    fieldReferences.Add(writerHelper.WriteCheckboxField(checkboxField));
                    break;
                case CheckboxesFieldDefinition checkboxesField:
                    fieldReferences.Add(writerHelper.WriteCheckboxesField(checkboxesField));
                    break;
                case RadioButtonFieldDefinition radioButtonField:
                    fieldReferences.Add(writerHelper.WriteRadioButtonField(radioButtonField));
                    break;
                case RadioButtonsFieldDefinition radioButtonsField:
                    fieldReferences.Add(writerHelper.WriteRadioButtonsField(radioButtonsField));
                    break;
                case PushButtonFieldDefinition pushButtonField:
                    fieldReferences.Add(writerHelper.WritePushButtonField(pushButtonField));
                    break;
                case ComboBoxFieldDefinition comboBoxField:
                    fieldReferences.Add(writerHelper.WriteComboBoxField(comboBoxField));
                    break;
                case ListBoxFieldDefinition listBoxField:
                    fieldReferences.Add(writerHelper.WriteListBoxField(listBoxField));
                    break;
                case SignatureFieldDefinition signatureField:
                    fieldReferences.Add(writerHelper.WriteSignatureField(signatureField));
                    break;
                default:
                    throw new NotSupportedException($"Unsupported field definition type: {field.GetType().Name}.");
            }
        }

        var dictionary = CreateAcroFormDictionary(builder, existingForm);
        dictionary[NameToken.Fields] = new ArrayToken(fieldReferences);
        dictionary[NameToken.NeedAppearances] = existingForm is null
            ? BooleanToken.True
            : existingForm.NeedAppearances ? BooleanToken.True : BooleanToken.False;

        var signatureFlags = existingForm?.SignatureFlags ?? 0;
        if (fields.Any(x => x is SignatureFieldDefinition))
        {
            signatureFlags |= SignatureFlags.SignaturesExist;
        }

        if (signatureFlags != 0)
        {
            dictionary[NameToken.SigFlags] = new NumericToken((int)signatureFlags);
        }

        var acroFormReference = builder.WriteToken(new DictionaryToken(dictionary));
        builder.AddCatalogEntry(NameToken.AcroForm, acroFormReference);
    }

    private List<IToken> GetExistingFieldReferences(PdfDocumentBuilder builder, AcroForm? existingForm)
    {
        if (existingForm is null || !existingForm.Dictionary.Data.TryGetValue(NameToken.Fields, out var existingFieldsToken))
        {
            return new List<IToken>(fields.Count);
        }

        var copiedFields = builder.CopyToken(sourceDocument.Structure.TokenScanner, existingFieldsToken);
        if (copiedFields is not ArrayToken copiedArray)
        {
            throw new InvalidOperationException("The AcroForm /Fields entry must be an array.");
        }

        var result = new List<IToken>(copiedArray.Data.Count + fields.Count);
        result.AddRange(copiedArray.Data);
        return result;
    }

    private Dictionary<NameToken, IToken> CreateAcroFormDictionary(PdfDocumentBuilder builder, AcroForm? existingForm)
    {
        var result = new Dictionary<NameToken, IToken>();
        if (existingForm is null)
        {
            return result;
        }

        foreach (var pair in existingForm.Dictionary.Data)
        {
            var key = NameToken.Create(pair.Key);
            if (key == NameToken.Fields || key == NameToken.NeedAppearances || key == NameToken.SigFlags)
            {
                continue;
            }

            result[key] = builder.CopyToken(sourceDocument.Structure.TokenScanner, pair.Value);
        }

        return result;
    }

    private class PdfFieldWriterHelper(PdfDocumentBuilder builder, IReadOnlyDictionary<int, PdfPageBuilder> pages)
    {
        public IndirectReferenceToken WriteTextField(TextFieldDefinition field)
        {
            var dictionary = CreateSingleWidgetFieldDictionary(NameToken.Tx, field, (uint)field.Flags);

            if (field.Value != null)
            {
                dictionary[NameToken.V] = new StringToken(field.Value);
            }

            if (field.MaxLength.HasValue)
            {
                dictionary[NameToken.MaxLen] = new NumericToken(field.MaxLength.Value);
            }

            return WriteFieldToken(field, new DictionaryToken(dictionary));
        }

        public IndirectReferenceToken WriteCheckboxField(CheckboxFieldDefinition field)
        {
            var dictionary = CreateSingleWidgetFieldDictionary(NameToken.Btn, field, (uint)field.Flags);

            var state = field.IsChecked ? field.OnStateName : NameToken.Off;
            dictionary[NameToken.V] = state;
            dictionary[NameToken.As] = state;
            return WriteFieldToken(field, new DictionaryToken(dictionary));
        }

        public IndirectReferenceToken WriteCheckboxesField(CheckboxesFieldDefinition field) =>
            WriteWidgetGroupField(NameToken.Btn, field, (uint)field.Flags, field.Checkboxes);

        public IndirectReferenceToken WriteRadioButtonField(RadioButtonFieldDefinition field)
        {
            var dictionary = CreateSingleWidgetFieldDictionary(
                NameToken.Btn, field, (uint)field.Flags);
            var state = field.IsSelected ? field.StateName : NameToken.Off;
            dictionary[NameToken.V] = state;
            dictionary[NameToken.As] = state;
            return WriteFieldToken(field, new DictionaryToken(dictionary));
        }

        public IndirectReferenceToken WriteRadioButtonsField(RadioButtonsFieldDefinition field) =>
            WriteWidgetGroupField(NameToken.Btn, field, (uint)field.Flags, field.RadioButtons);

        public IndirectReferenceToken WritePushButtonField(PushButtonFieldDefinition field)
        {
            var dictionary = CreateSingleWidgetFieldDictionary(NameToken.Btn, field, (uint)field.Flags);
            return WriteFieldToken(field, new DictionaryToken(dictionary));
        }

        public IndirectReferenceToken WriteComboBoxField(ComboBoxFieldDefinition field)
        {
            var dictionary = CreateSingleWidgetFieldDictionary(NameToken.Ch, field, (uint)field.Flags);
            dictionary[NameToken.Opt] = CreateOptionsArray(field.Options);
            if (field.SelectedOption != null)
            {
                dictionary[NameToken.V] = new StringToken(field.SelectedOption);
            }

            return WriteFieldToken(field, new DictionaryToken(dictionary));
        }

        public IndirectReferenceToken WriteListBoxField(ListBoxFieldDefinition field)
        {
            var dictionary = CreateSingleWidgetFieldDictionary(NameToken.Ch, field, (uint)field.Flags);
            dictionary[NameToken.Opt] = CreateOptionsArray(field.Options);
            dictionary[NameToken.V] = field.SelectedOptions.Count switch
            {
                1 => new StringToken(field.SelectedOptions[0]),
                > 1 => new ArrayToken(field.SelectedOptions.Select(x => new StringToken(x)).ToList()),
                _ => dictionary[NameToken.V]
            };

            if (field.TopIndex > 0)
            {
                dictionary[NameToken.Ti] = new NumericToken(field.TopIndex);
            }

            return WriteFieldToken(field, new DictionaryToken(dictionary));
        }

        public IndirectReferenceToken WriteSignatureField(SignatureFieldDefinition field)
        {
            var dictionary = CreateSingleWidgetFieldDictionary(NameToken.Sig, field, 0);
            return WriteFieldToken(field, new DictionaryToken(dictionary));
        }

        public IndirectReferenceToken WriteWidgetGroupField(
            NameToken fieldType,
            FieldDefinition field,
            uint flags,
            IReadOnlyList<WidgetItem> widgets)
        {
            var selectedWidget = widgets.FirstOrDefault(x => x.IsActive);
            var parentReference = builder.ReserveObjectNumber();
            var parentDictionary = new Dictionary<NameToken, IToken>
            {
                { NameToken.Ft, fieldType },
                { NameToken.T, new StringToken(field.PartialName) },
                { NameToken.Ff, new NumericToken(flags) }
            };

            if (selectedWidget != null)
            {
                parentDictionary[NameToken.V] = selectedWidget.StateName;
            }
            var childReferences = new List<IToken>(widgets.Count);

            foreach (var widget in widgets)
            {
                var childDictionary = CreateWidgetDictionary(field, widget.Bounds);
                childDictionary[NameToken.Parent] = parentReference;
                childDictionary[NameToken.As] = widget.IsActive ? widget.StateName : NameToken.Off;

                var childReference = WriteFieldToken(field, new DictionaryToken(childDictionary));
                childReferences.Add(childReference);
            }

            parentDictionary[NameToken.Kids] = new ArrayToken(childReferences);
            builder.WriteToken(new DictionaryToken(parentDictionary), parentReference);
            return parentReference;
        }

        private Dictionary<NameToken, IToken> CreateSingleWidgetFieldDictionary(
            NameToken fieldType, FieldDefinition field, uint flags)
        {
            var dictionary = CreateWidgetDictionary(field, field.Bounds);
            dictionary[NameToken.Ft] = fieldType;
            dictionary[NameToken.T] = new StringToken(field.PartialName);
            dictionary[NameToken.Ff] = new NumericToken(flags);
            return dictionary;
        }

        private Dictionary<NameToken, IToken> CreateWidgetDictionary(FieldDefinition field, PdfRectangle bounds) =>
            new()
            {
                { NameToken.Type, AnnotName },
                { NameToken.Subtype, WidgetName },
                { NameToken.Rect, RectangleToArray(bounds) },
                { NameToken.P, pages[field.PageNumber].PageReference }
            };

        private IndirectReferenceToken WriteFieldToken(FieldDefinition field, IToken token)
        {
            var reference = builder.WriteToken(token);
            AddAnnotation(pages[field.PageNumber], reference);
            return reference;
        }
    }

    private static void AddAnnotation(PdfPageBuilder page, IndirectReferenceToken annotation)
    {
        if (page.pageDictionary.TryGetValue(NameToken.Annots, out var existingAnnotations)
            && existingAnnotations is ArrayToken existingArray)
        {
            var updatedAnnotations = new List<IToken>(existingArray.Data) { annotation };
            page.pageDictionary[NameToken.Annots] = new ArrayToken(updatedAnnotations);
        }
        else
        {
            page.pageDictionary[NameToken.Annots] = new ArrayToken([annotation]);
        }
    }

    private static ArrayToken CreateOptionsArray(IEnumerable<string> options) =>
        new(options.Select(x => new StringToken(x)).ToList());

    private static ArrayToken RectangleToArray(PdfRectangle rectangle) => new(
        [
            new NumericToken(rectangle.BottomLeft.X),
            new NumericToken(rectangle.BottomLeft.Y),
            new NumericToken(rectangle.TopRight.X),
            new NumericToken(rectangle.TopRight.Y)
        ]);

    private void ValidateFieldInput(int pageNumber, string partialName, PdfRectangle bounds)
    {
        if (pageNumber <= 0 || pageNumber > sourceDocument.NumberOfPages)
        {
            throw new ArgumentOutOfRangeException(nameof(pageNumber), $"Page number must be between 1 and {sourceDocument.NumberOfPages}.");
        }

        if (string.IsNullOrWhiteSpace(partialName))
        {
            throw new ArgumentException("A non-empty field name is required.", nameof(partialName));
        }

        if (bounds.Width <= 0 || bounds.Height <= 0)
        {
            throw new ArgumentException("Field bounds must have positive width and height.", nameof(bounds));
        }
    }

    private void ValidateChoiceFieldInput(
        int pageNumber, string partialName, PdfRectangle bounds, IReadOnlyList<string> options)
    {
        ValidateFieldInput(pageNumber, partialName, bounds);

        if (options is null || options.Count == 0)
        {
            throw new ArgumentException("At least one choice option is required.", nameof(options));
        }
    }

    private void ValidateWidgetItems(
        int pageNumber, string partialName, IReadOnlyList<PdfRectangle> widgetBounds, string parameterName)
    {
        if (widgetBounds is null || widgetBounds.Count == 0)
        {
            throw new ArgumentException("At least one widget is required.", parameterName);
        }

        ValidateFieldInput(pageNumber, partialName, widgetBounds[0]);

        if (widgetBounds.Any(bounds => bounds.Width <= 0 || bounds.Height <= 0))
        {
            throw new ArgumentException("Widget bounds must have positive width and height.", parameterName);
        }
    }

    private static void ValidateTextFieldFlags(AcroTextFieldFlags flags)
    {
        const AcroTextFieldFlags allowedFlags =
            AcroTextFieldFlags.ReadOnly |
            AcroTextFieldFlags.Required |
            AcroTextFieldFlags.NoExport |
            AcroTextFieldFlags.Multiline |
            AcroTextFieldFlags.Password |
            AcroTextFieldFlags.FileSelect |
            AcroTextFieldFlags.DoNotSpellCheck |
            AcroTextFieldFlags.DoNotScroll |
            AcroTextFieldFlags.Comb |
            AcroTextFieldFlags.RichText;

        ValidateAllowedFlags(flags, allowedFlags, nameof(flags), "text field");
    }

    private static void ValidateCheckboxFieldFlags(AcroButtonFieldFlags flags)
    {
        const AcroButtonFieldFlags allowedFlags =
            AcroButtonFieldFlags.ReadOnly |
            AcroButtonFieldFlags.Required |
            AcroButtonFieldFlags.NoExport;

        ValidateAllowedFlags(flags, allowedFlags, nameof(flags), "checkbox field");
    }

    private static void ValidateRadioFieldFlags(AcroButtonFieldFlags flags)
    {
        const AcroButtonFieldFlags allowedFlags =
            AcroButtonFieldFlags.ReadOnly |
            AcroButtonFieldFlags.Required |
            AcroButtonFieldFlags.NoExport |
            AcroButtonFieldFlags.NoToggleToOff |
            AcroButtonFieldFlags.RadiosInUnison;

        ValidateAllowedFlags(flags, allowedFlags, nameof(flags), "radio button field");
    }

    private static void ValidatePushButtonFieldFlags(AcroButtonFieldFlags flags)
    {
        const AcroButtonFieldFlags allowedFlags =
            AcroButtonFieldFlags.ReadOnly |
            AcroButtonFieldFlags.Required |
            AcroButtonFieldFlags.NoExport;

        ValidateAllowedFlags(flags, allowedFlags, nameof(flags), "push button field");
    }

    private static void ValidateComboBoxFieldFlags(AcroChoiceFieldFlags flags)
    {
        const AcroChoiceFieldFlags allowedFlags =
            AcroChoiceFieldFlags.ReadOnly |
            AcroChoiceFieldFlags.Required |
            AcroChoiceFieldFlags.NoExport |
            AcroChoiceFieldFlags.Edit |
            AcroChoiceFieldFlags.Sort |
            AcroChoiceFieldFlags.DoNotSpellCheck |
            AcroChoiceFieldFlags.CommitOnSelectionChange;

        ValidateAllowedFlags(flags, allowedFlags, nameof(flags), "combo box field");
    }

    private static void ValidateListBoxFieldFlags(AcroChoiceFieldFlags flags)
    {
        const AcroChoiceFieldFlags allowedFlags =
            AcroChoiceFieldFlags.ReadOnly |
            AcroChoiceFieldFlags.Required |
            AcroChoiceFieldFlags.NoExport |
            AcroChoiceFieldFlags.Sort |
            AcroChoiceFieldFlags.MultiSelect |
            AcroChoiceFieldFlags.CommitOnSelectionChange;

        ValidateAllowedFlags(flags, allowedFlags, nameof(flags), "list box field");
    }

    private static void ValidateAllowedFlags<TEnum>(TEnum flags, TEnum allowedFlags, string parameterName, string fieldType)
        where TEnum : struct, Enum
    {
        var provided = Convert.ToUInt64(flags);
        var allowed = Convert.ToUInt64(allowedFlags);
        var invalid = provided & ~allowed;

        if (invalid == 0)
        {
            return;
        }

        throw new ArgumentOutOfRangeException(
            parameterName,
            flags,
            $"The value contains flags that are not valid for a {fieldType}: {(TEnum)Enum.ToObject(typeof(TEnum), invalid)}.");
    }

    private void ValidateNewFieldNames(AcroForm? existingForm)
    {
        if (fields.Count == 0)
        {
            return;
        }

        var addedNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var field in fields)
        {
            if (!addedNames.Add(field.PartialName))
            {
                throw new InvalidOperationException($"A field with fully qualified name '{field.PartialName}' was already added to this writer.");
            }

            if (existingForm != null && existingForm.TryGetField(field.PartialName, out _))
            {
                throw new InvalidOperationException($"A field with fully qualified name '{field.PartialName}' already exists in the source document.");
            }
        }
    }

    private static NameToken GetStateName(string stateName)
    {
        if (string.IsNullOrWhiteSpace(stateName) ||
            string.Equals(stateName, NameToken.OffAcroform.Data, StringComparison.OrdinalIgnoreCase))
        {
            return YesName;
        }

        return NameToken.Create(stateName);
    }
}