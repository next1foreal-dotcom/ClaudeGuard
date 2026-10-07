using System;
using System.Collections.Generic;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

// Existing status text remains the single source of state.
public sealed class ClaudeGuardIconConverter : IValueConverter {
    public Dictionary<string, Geometry> Icons { get; set; }
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) {
        string mark = System.Convert.ToString(value, CultureInfo.InvariantCulture);
        string name = "circle";
        if (mark == "\u2713") name = "check";
        else if (mark == "!") name = "circle-alert";
        else if (mark == "?") name = "circle-help";
        else if (mark == "\u2022" || mark == "\u2026") name = "loader-circle";
        else if (mark == "\u2013") name = "minus";
        return Icons[name];
    }
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) {
        throw new NotSupportedException();
    }
}