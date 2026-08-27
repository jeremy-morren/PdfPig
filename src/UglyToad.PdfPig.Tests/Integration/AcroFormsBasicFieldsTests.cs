namespace UglyToad.PdfPig.Tests.Integration
{
    using AcroForms;
    using AcroForms.Fields;

    public class AcroFormsBasicFieldsTests
    {
        private static string GetFilename()
        {
            return IntegrationHelpers.GetDocumentPath("AcroFormsBasicFields");
        }

        [Fact]
        public void TryGetFormNotNull()
        {
            using (var document = PdfDocument.Open(GetFilename(), ParsingOptions.LenientParsingOff))
            {
                document.TryGetForm(out var form);
                Assert.NotNull(form);
            }
        }

        [Fact]
        public void TryGetFormDisposedThrows()
        {
            var document = PdfDocument.Open(GetFilename());

            document.Dispose();

            Action action = () => document.TryGetForm(out _);

            Assert.Throws<ObjectDisposedException>(action);
        }

        [Fact]
        public void TryGetGetsAllFormFields()
        {
            using (var document = PdfDocument.Open(GetFilename(), ParsingOptions.LenientParsingOff))
            {
                document.TryGetForm(out var form);
                Assert.Equal(18, form.Fields.Count);
            }
        }

        [Fact]
        public void TryGetFormFieldsByPage()
        {
            using (var document = PdfDocument.Open(GetFilename(), ParsingOptions.LenientParsingOff))
            {
                document.TryGetForm(out var form);
                var fields = form.GetFieldsForPage(1).ToList();
                Assert.Equal(18, fields.Count);
            }
        }

        [Fact]
        public void TryGetGetsFullyQualifiedFieldNames()
        {
            using (var document = PdfDocument.Open(GetFilename(), ParsingOptions.LenientParsingOff))
            {
                document.TryGetForm(out var form);

                var fields = form.GetFields().ToList();

                Assert.All(fields.Where(x => x.Information.PartialName != null), x => Assert.False(string.IsNullOrWhiteSpace(x.Information.FullyQualifiedName)));
                Assert.Contains(fields, x => x.Information.FullyQualifiedName != x.Information.PartialName);
            }
        }

        [Fact]
        public void TryGetCanResolveFieldByReferenceAndFullyQualifiedName()
        {
            using (var document = PdfDocument.Open(GetFilename(), ParsingOptions.LenientParsingOff))
            {
                document.TryGetForm(out var form);

                var field = form.GetFields().First(x => x.Information.Reference.HasValue && !string.IsNullOrWhiteSpace(x.Information.FullyQualifiedName));

                Assert.True(form.TryGetField(field.Information.Reference.Value, out var byReference));
                Assert.Same(field, byReference);

                Assert.True(form.TryGetField(field.Information.FullyQualifiedName, out var byName));
                Assert.Same(field, byName);

                Assert.False(form.TryGetField("missing.field", out _));
            }
        }

        [Fact]
        public void TryGetGetsRadioButtonState()
        {
            using (var document = PdfDocument.Open(GetFilename(), ParsingOptions.LenientParsingOff))
            {
                document.TryGetForm(out var form);
                var radioButtons = form.Fields.OfType<AcroRadioButtonsField>().ToList();

                Assert.Equal(2, radioButtons.Count);

                // ReSharper disable once PossibleInvalidOperationException
                var ordered = radioButtons.OrderBy(x => x.Children.Min(y => y.Bounds.Value.Left)).ToList();

                var left = ordered[0];

                Assert.Equal(2, left.Children.Count);
                foreach (var acroFieldBase in left.Children)
                {
                    var button = Assert.IsType<AcroRadioButtonField>(acroFieldBase);
                    Assert.False(button.IsSelected);
                }

                var right = ordered[1];
                Assert.Equal(2, right.Children.Count);

                var buttonOn = Assert.IsType<AcroRadioButtonField>(right.Children[0]);
                Assert.True(buttonOn.IsSelected);

                var buttonOff = Assert.IsType<AcroRadioButtonField>(right.Children[1]);
                Assert.False(buttonOff.IsSelected);
            }
        }
    }
}
