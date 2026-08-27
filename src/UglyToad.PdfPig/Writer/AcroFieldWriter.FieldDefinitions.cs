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
partial class AcroFieldWriter
{
    /// <summary>
    /// Base definition for a form field that should be written on a page.
    /// </summary>
    public abstract class FieldDefinition
    {
        public int PageNumber { get; }

        public string PartialName { get; }

        public PdfRectangle Bounds { get; }

        protected FieldDefinition(int pageNumber, string partialName, PdfRectangle bounds)
        {
            PageNumber = pageNumber;
            PartialName = partialName;
            Bounds = bounds;
        }
    }

    /// <summary>
    /// Definition for a text field.
    /// </summary>
    public sealed class TextFieldDefinition : FieldDefinition
    {
        public string? Value { get; }

        public AcroTextFieldFlags Flags { get; }

        public int? MaxLength { get; }

        public TextFieldDefinition(
            int pageNumber,
            string partialName,
            PdfRectangle bounds,
            string? value,
            AcroTextFieldFlags flags,
            int? maxLength)
            : base(pageNumber, partialName, bounds)
        {
            Value = value;
            Flags = flags;
            MaxLength = maxLength;
        }
    }

    /// <summary>
    /// Definition for a single checkbox field.
    /// </summary>
    public sealed class CheckboxFieldDefinition : FieldDefinition
    {
        public bool IsChecked { get; }

        public NameToken OnStateName { get; }

        public AcroButtonFieldFlags Flags { get; }

        public CheckboxFieldDefinition(
            int pageNumber,
            string partialName,
            PdfRectangle bounds,
            bool isChecked,
            NameToken onStateName,
            AcroButtonFieldFlags flags)
            : base(pageNumber, partialName, bounds)
        {
            IsChecked = isChecked;
            OnStateName = onStateName;
            Flags = flags;
        }
    }

    /// <summary>
    /// Definition for a checkbox group field with multiple widgets.
    /// </summary>
    public sealed class CheckboxesFieldDefinition : FieldDefinition
    {
        public IReadOnlyList<WidgetItem> Checkboxes { get; }

        public AcroButtonFieldFlags Flags { get; }

        public CheckboxesFieldDefinition(
            int pageNumber,
            string partialName,
            IReadOnlyList<WidgetItem> checkboxes,
            AcroButtonFieldFlags flags)
            : base(pageNumber, partialName, checkboxes[0].Bounds)
        {
            Checkboxes = checkboxes;
            Flags = flags;
        }
    }

    /// <summary>
    /// Definition for a single radio button field.
    /// </summary>
    public sealed class RadioButtonFieldDefinition : FieldDefinition
    {
        public bool IsSelected { get; }

        public NameToken StateName { get; }

        public AcroButtonFieldFlags Flags { get; }

        public RadioButtonFieldDefinition(
            int pageNumber,
            string partialName,
            PdfRectangle bounds,
            bool isSelected,
            NameToken stateName,
            AcroButtonFieldFlags flags)
            : base(pageNumber, partialName, bounds)
        {
            IsSelected = isSelected;
            StateName = stateName;
            Flags = flags;
        }
    }

    /// <summary>
    /// Definition for a radio button group field with multiple widgets.
    /// </summary>
    public sealed class RadioButtonsFieldDefinition : FieldDefinition
    {
        public IReadOnlyList<WidgetItem> RadioButtons { get; }

        public AcroButtonFieldFlags Flags { get; }

        public RadioButtonsFieldDefinition(
            int pageNumber,
            string partialName,
            IReadOnlyList<WidgetItem> radioButtons,
            AcroButtonFieldFlags flags)
            : base(pageNumber, partialName, radioButtons[0].Bounds)
        {
            RadioButtons = radioButtons;
            Flags = flags;
        }
    }

    /// <summary>
    /// Definition for a push button field.
    /// </summary>
    public sealed class PushButtonFieldDefinition : FieldDefinition
    {
        public AcroButtonFieldFlags Flags { get; }

        public PushButtonFieldDefinition(
            int pageNumber,
            string partialName,
            PdfRectangle bounds,
            AcroButtonFieldFlags flags)
            : base(pageNumber, partialName, bounds)
        {
            Flags = flags;
        }
    }

    /// <summary>
    /// Definition for a combo box field.
    /// </summary>
    public sealed class ComboBoxFieldDefinition : FieldDefinition
    {
        public IReadOnlyList<string> Options { get; }

        public string? SelectedOption { get; }

        public AcroChoiceFieldFlags Flags { get; }

        public ComboBoxFieldDefinition(
            int pageNumber,
            string partialName,
            PdfRectangle bounds,
            IReadOnlyList<string> options,
            string? selectedOption,
            AcroChoiceFieldFlags flags)
            : base(pageNumber, partialName, bounds)
        {
            Options = options;
            SelectedOption = selectedOption;
            Flags = flags;
        }
    }

    /// <summary>
    /// Definition for a list box field.
    /// </summary>
    public sealed class ListBoxFieldDefinition : FieldDefinition
    {
        public IReadOnlyList<string> Options { get; }

        public IReadOnlyList<string> SelectedOptions { get; }

        public AcroChoiceFieldFlags Flags { get; }

        public int TopIndex { get; }

        public ListBoxFieldDefinition(
            int pageNumber,
            string partialName,
            PdfRectangle bounds,
            IReadOnlyList<string> options,
            IReadOnlyList<string> selectedOptions,
            AcroChoiceFieldFlags flags,
            int topIndex)
            : base(pageNumber, partialName, bounds)
        {
            Options = options;
            SelectedOptions = selectedOptions;
            Flags = flags;
            TopIndex = topIndex;
        }
    }

    /// <summary>
    /// Definition for an unsigned signature field.
    /// </summary>
    public sealed class SignatureFieldDefinition : FieldDefinition
    {
        public SignatureFieldDefinition(int pageNumber, string partialName, PdfRectangle bounds)
            : base(pageNumber, partialName, bounds)
        {
        }
    }

    public sealed class WidgetItem
    {
        public PdfRectangle Bounds { get; }
        public NameToken StateName { get; }
        public bool IsActive { get; }

        public WidgetItem(PdfRectangle bounds, NameToken stateName, bool isActive)
        {
            Bounds = bounds;
            StateName = stateName;
            IsActive = isActive;
        }
    }
}