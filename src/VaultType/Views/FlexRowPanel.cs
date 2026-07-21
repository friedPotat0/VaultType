using System.Windows;
using Panel = System.Windows.Controls.Panel;

namespace VaultType.Views;

// CSS "display:flex; gap:G" with every child "flex: 1 1 auto": each child keeps its content
// width and the leftover space is split equally. Used for the design's segmented pill rows.
public sealed class FlexRowPanel : Panel
{
    public static readonly DependencyProperty GapProperty = DependencyProperty.Register(
        nameof(Gap), typeof(double), typeof(FlexRowPanel),
        new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsMeasure));

    public double Gap { get => (double)GetValue(GapProperty); set => SetValue(GapProperty, value); }

    protected override Size MeasureOverride(Size availableSize)
    {
        double w = 0, h = 0;
        foreach (UIElement c in InternalChildren)
        {
            c.Measure(new Size(double.PositiveInfinity, availableSize.Height));
            w += c.DesiredSize.Width;
            h = Math.Max(h, c.DesiredSize.Height);
        }
        if (InternalChildren.Count > 1) w += Gap * (InternalChildren.Count - 1);
        return new Size(double.IsInfinity(availableSize.Width) ? w : Math.Max(w, availableSize.Width), h);
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        int n = InternalChildren.Count;
        if (n == 0) return finalSize;
        double content = 0;
        foreach (UIElement c in InternalChildren) content += c.DesiredSize.Width;
        double leftover = Math.Max(0, finalSize.Width - Gap * (n - 1) - content);
        double grow = leftover / n;
        double x = 0;
        foreach (UIElement c in InternalChildren)
        {
            double w = c.DesiredSize.Width + grow;
            c.Arrange(new Rect(x, 0, w, finalSize.Height));
            x += w + Gap;
        }
        return finalSize;
    }
}
