// Resolves the name clash between WPF (System.Windows) and
// WinForms (System.Windows.Forms / System.Drawing) in favour of WPF.
// WinForms is only used for the tray icon (NotifyIcon), fully qualified there.

global using Application = System.Windows.Application;
global using MessageBox = System.Windows.MessageBox;
global using Clipboard = System.Windows.Clipboard;
global using Color = System.Windows.Media.Color;
global using Colors = System.Windows.Media.Colors;
global using Brush = System.Windows.Media.Brush;
global using Brushes = System.Windows.Media.Brushes;
global using SolidColorBrush = System.Windows.Media.SolidColorBrush;
global using FontFamily = System.Windows.Media.FontFamily;
global using Point = System.Windows.Point;
global using Size = System.Windows.Size;
global using KeyEventArgs = System.Windows.Input.KeyEventArgs;
global using MouseEventArgs = System.Windows.Input.MouseEventArgs;
global using MouseButtonEventArgs = System.Windows.Input.MouseButtonEventArgs;
global using MenuItem = System.Windows.Controls.MenuItem;
