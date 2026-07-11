using System.Windows.Markup;

namespace VaultType;

// XAML helper: {local:Tr some.key} resolves to the localized string at load time.
[MarkupExtensionReturnType(typeof(string))]
public sealed class TrExtension : MarkupExtension
{
    public string Key { get; set; } = "";

    public TrExtension() { }
    public TrExtension(string key) { Key = key; }

    public override object ProvideValue(IServiceProvider serviceProvider) => Loc.T(Key);
}
