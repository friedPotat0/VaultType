using System.ComponentModel;
using System.Windows;
using System.Windows.Media;
using VaultType.Models;

namespace VaultType;

// View model around a VaultItem plus its (async-loaded) favicon.
public sealed class ItemVM : INotifyPropertyChanged
{
    public VaultItem Item { get; }
    public ItemVM(VaultItem item) { Item = item; }

    public string Name => Item.Name;
    public string Username => Item.Username;
    public bool HasTotp => Item.HasTotp;
    public bool HasSequence => !string.IsNullOrWhiteSpace(Item.CustomSequence);
    public string Sequence => Item.CustomSequence ?? "";
    public string SequenceHint => Loc.T("picker.seqHint") + "\n" + Sequence;
    public string IconDomain => Item.PrimaryHost;

    private ImageSource? _icon;
    public ImageSource? Icon
    {
        get => _icon;
        set
        {
            _icon = value;
            Raise(nameof(Icon));
            Raise(nameof(AvatarVisibility));
            Raise(nameof(IconVisibility));
        }
    }

    public Visibility AvatarVisibility => _icon == null ? Visibility.Visible : Visibility.Collapsed;
    public Visibility IconVisibility => _icon == null ? Visibility.Collapsed : Visibility.Visible;

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Raise(string p) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));
}
