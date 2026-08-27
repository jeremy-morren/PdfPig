namespace UglyToad.PdfPig.Tests.Writer;

using UglyToad.PdfPig.AcroForms;
using UglyToad.PdfPig.AcroForms.Fields;
using UglyToad.PdfPig.Content;
using UglyToad.PdfPig.Core;
using UglyToad.PdfPig.Tests.Integration;
using UglyToad.PdfPig.Writer;

public class AcroFieldWriterTests
{
    [Fact]
    public void CanRoundTripTextField()
    {
        using var writtenDocument = RoundTrip(writer =>
            writer.AddTextField(
                1,
                "TextField",
                new PdfRectangle(10, 10, 110, 30),
                "Hello form",
                AcroTextFieldFlags.Multiline,
                50));

        var textField = AssertSingleField<AcroTextField>(writtenDocument);
        Assert.Equal("TextField", textField.Information.PartialName);
        Assert.Equal("Hello form", textField.Value);
        Assert.Equal(50, textField.MaxLength);
        Assert.True(textField.IsMultiline);
        Assert.Equal(new PdfRectangle(10, 10, 110, 30), textField.Bounds);
        Assert.Equal(1, textField.PageNumber);
    }

    [Theory]
    [InlineData(1, "CheckboxGroup", true, "True", "True", AcroButtonFieldFlags.Required)]
    [InlineData(2, "CheckboxField", false, "Checked", "OFF", AcroButtonFieldFlags.NoExport)]
    public void CanRoundTripCheckboxField(int pageNumber, string partialName, bool isChecked, string onStateName, string expectedCurrentValue, AcroButtonFieldFlags flags)
    {
        using var writtenDocument = RoundTrip(writer =>
            writer.AddCheckboxField(
                pageNumber,
                partialName,
                new PdfRectangle(10, 10, 40, 40),
                isChecked,
                onStateName,
                flags));

        var checkboxField = AssertSingleField<AcroCheckboxField>(writtenDocument);
        Assert.Equal(isChecked, checkboxField.IsChecked);
        Assert.Equal(expectedCurrentValue, checkboxField.CurrentValue.Data);
        Assert.Equal(pageNumber, checkboxField.PageNumber);
        Assert.Equal(flags, checkboxField.Flags);
    }

    [Fact]
    public void CanRoundTripCheckboxesField()
    {
        const AcroButtonFieldFlags flags = AcroButtonFieldFlags.Required | AcroButtonFieldFlags.NoExport;

        using var writtenDocument = RoundTrip(writer =>
            writer.AddCheckboxesField(
                1,
                "CheckboxGroup",
                [
                    (new PdfRectangle(10, 10, 30, 30), "First", true),
                    (new PdfRectangle(40, 10, 60, 30), "Second", false)
                ],
                flags));

        var group = AssertSingleField<AcroCheckboxesField>(writtenDocument);
        Assert.Equal(2, group.Children.Count);
        Assert.True(Assert.IsType<AcroCheckboxField>(group.Children[0]).IsChecked);
        Assert.False(Assert.IsType<AcroCheckboxField>(group.Children[1]).IsChecked);
        Assert.Equal(flags, group.Flags);
    }

    [Fact]
    public void CanRoundTripRadioButtonField()
    {
        using var writtenDocument = RoundTrip(writer =>
            writer.AddRadioButtonField(1, "RadioButtonField", new PdfRectangle(10, 10, 30, 30), true, "ChoiceA"));

        var radioButton = AssertSingleField<AcroRadioButtonField>(writtenDocument);
        Assert.True(radioButton.IsSelected);
        Assert.Equal("ChoiceA", radioButton.CurrentValue.Data);
    }

    [Fact]
    public void CanRoundTripRadioButtonsField()
    {
        using var writtenDocument = RoundTrip(writer =>
            writer.AddRadioButtonsField(1, "RadioButtonsField",
            [
                (new PdfRectangle(10, 10, 30, 30), "Left", false),
                (new PdfRectangle(40, 10, 60, 30), "Right", true)
            ]));

        var group = AssertSingleField<AcroRadioButtonsField>(writtenDocument);
        Assert.Equal(2, group.Children.Count);
        Assert.False(Assert.IsType<AcroRadioButtonField>(group.Children[0]).IsSelected);
        Assert.True(Assert.IsType<AcroRadioButtonField>(group.Children[1]).IsSelected);
    }

    [Fact]
    public void CanRoundTripPushButtonField()
    {
        using var writtenDocument = RoundTrip(writer =>
            writer.AddPushButtonField(1, "PushButtonField", new PdfRectangle(10, 10, 80, 30)));

        var pushButton = AssertSingleField<AcroPushButtonField>(writtenDocument);
        Assert.Equal(AcroFieldType.PushButton, pushButton.FieldType);
    }

    [Fact]
    public void CanRoundTripComboBoxField()
    {
        using var writtenDocument = RoundTrip(writer =>
            writer.AddComboBoxField(1, "ComboBoxField", new PdfRectangle(10, 10, 120, 30), ["Red", "Blue", "Green"], "Blue"));

        var comboBox = AssertSingleField<AcroComboBoxField>(writtenDocument);
        Assert.Equal(new[] { "Blue" }, comboBox.SelectedOptions.ToArray());
        Assert.Equal(new[] { "Red", "Blue", "Green" }, comboBox.Options.Select(x => x.Name).ToArray());
    }

    [Fact]
    public void CanRoundTripListBoxField()
    {
        using var writtenDocument = RoundTrip(writer =>
            writer.AddListBoxField(1, "ListBoxField", new PdfRectangle(10, 10, 120, 60), ["Alpha", "Beta", "Gamma"], ["Beta"], topIndex: 1));

        var listBox = AssertSingleField<AcroListBoxField>(writtenDocument);
        Assert.Equal(new[] { "Beta" }, listBox.SelectedOptions.ToArray());
        Assert.Equal(1, listBox.TopIndex);
        Assert.Equal(new[] { "Alpha", "Beta", "Gamma" }, listBox.Options.Select(x => x.Name).ToArray());
    }

    [Fact]
    public void CanRoundTripSignatureField()
    {
        using var writtenDocument = RoundTrip(writer =>
            writer.AddSignatureField(1, "SignatureField", new PdfRectangle(10, 10, 120, 40)));

        var signatureField = AssertSingleField<AcroSignatureField>(writtenDocument);
        Assert.True(writtenDocument.TryGetForm(out var form));
        Assert.False(signatureField.IsSigned);
        Assert.Null(signatureField.SignatureValue);
        Assert.True(form.SignatureFlags.HasFlag(SignatureFlags.SignaturesExist));
    }

    [Fact]
    public void CanAddSignatureFieldToExistingPdfWithoutForm()
    {
        using var sourceDocument = PdfDocument.Open(IntegrationHelpers.GetDocumentPath("Single Page Simple - from inkscape.pdf"));
        var writer = new AcroFieldWriter(sourceDocument);
        writer.AddSignatureField(1, "SignatureField", new PdfRectangle(10, 10, 120, 40));

        using var output = new MemoryStream();
        writer.Write(output);

        using var writtenDocument = PdfDocument.Open(output.ToArray());
        var signatureField = AssertSingleField<AcroSignatureField>(writtenDocument);
        Assert.False(signatureField.IsSigned);
    }

    [Fact]
    public void CanAddSignatureFieldToExistingAcroFormDocument()
    {
        using var sourceDocument = PdfDocument.Open(IntegrationHelpers.GetDocumentPath("AcroFormsBasicFields.pdf"));
        Assert.True(sourceDocument.TryGetForm(out var sourceForm));
        var sourceNames = sourceForm.GetFields()
            .Select(x => x.Information.FullyQualifiedName)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Take(3)
            .ToArray();

        var writer = new AcroFieldWriter(sourceDocument);
        writer.AddSignatureField(1, "SignatureField", new PdfRectangle(10, 10, 120, 40));

        using var output = new MemoryStream();
        writer.Write(output);

        using var writtenDocument = PdfDocument.Open(output.ToArray());
        Assert.True(writtenDocument.TryGetForm(out var form));
        Assert.True(form.TryGetField("SignatureField", out var addedField));
        Assert.IsType<AcroSignatureField>(addedField);
        Assert.Equal(sourceForm.Fields.Count + 1, form.Fields.Count);
        Assert.All(sourceNames, name => Assert.True(form.TryGetField(name!, out _)));
    }

    [Fact]
    public void ThrowsWhenAddingTextFieldWithUnknownFlags()
    {
        using var sourceDocument = PdfDocument.Open(Create2BlankPages());
        var writer = new AcroFieldWriter(sourceDocument);

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            writer.AddTextField(1, "TextField", new PdfRectangle(10, 10, 110, 30), flags: (AcroTextFieldFlags)(1u << 31)));

        Assert.Equal("flags", exception.ParamName);
    }

    [Fact]
    public void ThrowsWhenAddingCheckboxFieldWithRadioFlags()
    {
        using var sourceDocument = PdfDocument.Open(Create2BlankPages());
        var writer = new AcroFieldWriter(sourceDocument);

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            writer.AddCheckboxField(1, "CheckboxField", new PdfRectangle(10, 10, 40, 40), true, flags: AcroButtonFieldFlags.Radio));

        Assert.Equal("flags", exception.ParamName);
    }

    [Fact]
    public void ThrowsWhenAddingCheckboxesFieldWithRadioFlags()
    {
        using var sourceDocument = PdfDocument.Open(Create2BlankPages());
        var writer = new AcroFieldWriter(sourceDocument);

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            writer.AddCheckboxesField(
                1,
                "CheckboxGroup",
                [
                    (new PdfRectangle(10, 10, 30, 30), "First", true),
                    (new PdfRectangle(40, 10, 60, 30), "Second", false)
                ],
                AcroButtonFieldFlags.Radio));

        Assert.Equal("flags", exception.ParamName);
    }

    [Fact]
    public void ThrowsWhenAddingPushButtonFieldWithRadioFlags()
    {
        using var sourceDocument = PdfDocument.Open(Create2BlankPages());
        var writer = new AcroFieldWriter(sourceDocument);

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            writer.AddPushButtonField(1, "PushButtonField", new PdfRectangle(10, 10, 80, 30), AcroButtonFieldFlags.Radio));

        Assert.Equal("flags", exception.ParamName);
    }

    [Fact]
    public void ThrowsWhenAddingComboBoxFieldWithMultiSelectFlag()
    {
        using var sourceDocument = PdfDocument.Open(Create2BlankPages());
        var writer = new AcroFieldWriter(sourceDocument);

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            writer.AddComboBoxField(1, "ComboBoxField", new PdfRectangle(10, 10, 120, 30), ["Red", "Blue"], flags: AcroChoiceFieldFlags.MultiSelect));

        Assert.Equal("flags", exception.ParamName);
    }

    [Fact]
    public void ThrowsWhenAddingListBoxFieldWithEditFlag()
    {
        using var sourceDocument = PdfDocument.Open(Create2BlankPages());
        var writer = new AcroFieldWriter(sourceDocument);

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            writer.AddListBoxField(1, "ListBoxField", new PdfRectangle(10, 10, 120, 60), ["Alpha", "Beta"], flags: AcroChoiceFieldFlags.Edit));

        Assert.Equal("flags", exception.ParamName);
    }

    [Fact]
    public void ThrowsWhenAddingDuplicateFieldNameWithinWriter()
    {
        using var sourceDocument = PdfDocument.Open(Create2BlankPages());
        var writer = new AcroFieldWriter(sourceDocument);
        writer.AddTextField(1, "DuplicateName", new PdfRectangle(10, 10, 100, 30));
        writer.AddSignatureField(1, "DuplicateName", new PdfRectangle(10, 40, 120, 70));

        var exception = Assert.Throws<InvalidOperationException>(() => writer.Build());
        Assert.Contains("DuplicateName", exception.Message);
    }

    [Fact]
    public void ThrowsWhenAddingFieldNameThatAlreadyExistsInSourceDocument()
    {
        using var sourceDocument = PdfDocument.Open(IntegrationHelpers.GetDocumentPath("AcroFormsBasicFields.pdf"));
        Assert.True(sourceDocument.TryGetForm(out var sourceForm));
        var existingName = sourceForm.GetFields()
            .Select(x => x.Information.FullyQualifiedName)
            .First(x => !string.IsNullOrWhiteSpace(x));

        var writer = new AcroFieldWriter(sourceDocument);
        writer.AddSignatureField(1, existingName!, new PdfRectangle(10, 10, 120, 40));

        var exception = Assert.Throws<InvalidOperationException>(() => writer.Build());
        Assert.Contains(existingName!, exception.Message);
    }

    private static TField AssertSingleField<TField>(PdfDocument document)
        where TField : AcroFieldBase
    {
        Assert.True(document.TryGetForm(out var form));
        return Assert.IsType<TField>(Assert.Single(form.Fields));
    }

    private static PdfDocument RoundTrip(Action<AcroFieldWriter> apply)
    {
        using var sourceDocument = PdfDocument.Open(Create2BlankPages());
        var writer = new AcroFieldWriter(sourceDocument);
        apply(writer);
        Assert.NotEmpty(writer.GetFields());

        using var output = new MemoryStream();
        writer.Write(output);
        return PdfDocument.Open(output.ToArray());
    }

    private static byte[] Create2BlankPages()
    {
        using var builder = new PdfDocumentBuilder();
        builder.AddPage(PageSize.A4);
        builder.AddPage(PageSize.Letter);
        return builder.Build();
    }
}