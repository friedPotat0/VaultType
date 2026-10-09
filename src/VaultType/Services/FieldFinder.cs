using System.Threading;
using System.Windows.Automation;
using VaultType.Security;

namespace VaultType.Services;

// Locates an input field in the target window by its label or its programmatic id and moves the
// caret there.
//
// This only ever *finds* and *focuses*. Values are always typed as simulated keystrokes, never
// written through the automation interface - ValuePattern.SetValue takes a managed string, which
// would defeat the locked-buffer handling every secret goes through.
//
// The element list is cached for the duration of one auto-type run and thrown away once a lookup
// comes up empty, so a field that only appears after the previous one was filled is still found.
public sealed class FieldFinder
{
    private readonly IntPtr _hwnd;
    private List<Candidate>? _cache;

    // Bumped on every rescan. DetectedField carries the value it was created under, so an index
    // from before a rescan can't be used to focus what now sits at that position.
    private int _generation;

    // A backstop against pathological pages, not a working limit - real forms are far below this.
    private const int MaxCandidates = 2000;

    // Chromium-based browsers only build a page's accessibility tree once a client asks for it, and
    // drop it again after a while without one. The first scan after switching back to the browser
    // then sees the toolbar but none of the form, so a scan without a single recognisable field is
    // repeated a few times while the page catches up.
    private static readonly int[] SettleDelaysMs = { 100, 200, 300 };

    // UIA frameworks of browser content. Their IsOffscreen means "outside the viewport", which also
    // covers every field further down a long form - focusing such a field scrolls it into view.
    private static readonly HashSet<string> BrowserFrameworks = new(StringComparer.OrdinalIgnoreCase) { "Chrome", "Gecko" };

    private sealed class Candidate
    {
        public AutomationElement Element = null!;
        public string Label = "";
        public string Id = "";
        public bool Required;
        public bool IsChoice;
        public int[] RuntimeId = Array.Empty<int>();
    }

    public sealed class DetectedField
    {
        public FieldGroup Group;
        public int GroupMatchLength;   // how specific the group match was, for weighing custom fields
        public string Label = "";      // normalised, for matching custom field names
        public string Id = "";         // normalised
        public bool Required;
        public bool IsChoice;          // a drop-down list rather than a text box
        internal int Index;
        internal int Generation;
    }

    public FieldFinder(IntPtr hwnd) => _hwnd = hwnd;

    // True when the target window exposes any input field at all. Used to tell "nothing matched
    // this term" apart from "this application tells us nothing", which get different messages.
    public bool AnyFieldsVisible() => Cached().Count > 0;

    private List<Candidate> Cached()
    {
        if (_cache == null)
        {
            _cache = Scan();
            for (int i = 0; i < SettleDelaysMs.Length && !AnyRecognised(_cache); i++)
            {
                Thread.Sleep(SettleDelaysMs[i]);
                _cache = Scan();
            }
            _generation++;
        }
        return _cache;
    }

    private static bool AnyRecognised(List<Candidate> list)
        => list.Any(c => Classify(c.Label, c.Id, out _) != FieldGroup.None);

    // Every input field this form exposes, in document order starting at the caret, each with the
    // group recognised for it (if any) and whether the form marks it as required.
    public List<DetectedField> DetectFields()
    {
        var list = Cached();
        var result = new List<DetectedField>();
        for (int i = StartIndex(list); i < list.Count; i++)
        {
            var c = list[i];
            var group = Classify(c.Label, c.Id, out int matchLen);
            result.Add(new DetectedField
            {
                Group = group,
                GroupMatchLength = matchLen,
                Label = c.Label,
                Id = c.Id,
                Required = c.Required,
                IsChoice = c.IsChoice,
                Index = i,
                Generation = _generation,
            });
        }
        return result;
    }

    // Focus a field the caller picked out of DetectFields. False when the list has been rescanned
    // since, the element is gone, or the focus didn't take - the caller then skips that field
    // instead of typing into the wrong one.
    public bool FocusAt(DetectedField field)
    {
        var list = _cache;
        if (list == null || field.Generation != _generation) return false;
        if (field.Index < 0 || field.Index >= list.Count) return false;
        return SetFocus(list[field.Index]);
    }

    // ---- drop-down lists ----

    private static readonly Condition OptionCondition =
        new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.ListItem);
    private static readonly Condition TextCondition =
        new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Text);

    // Pick the entry of a drop-down list that isMatch accepts, instead of typing into it. Covers
    // native <select> boxes, whose entries the tree lists even while closed, and the script-built
    // lists many checkouts use, whose entries only exist once the list is open. False when the field
    // isn't a list, no entry matched, or the choice didn't stick - the caller then types instead.
    // Opening and closing go through the automation interface first; the keyboard callbacks are
    // the fallback for lists that don't support it.
    public bool SelectOptionAt(DetectedField field, Func<string, bool> isMatch,
                               Action openWithKeyboard, Action closeWithKeyboard)
    {
        var list = _cache;
        if (list == null || field.Generation != _generation) return false;
        if (field.Index < 0 || field.Index >= list.Count || !list[field.Index].IsChoice) return false;
        var box = list[field.Index].Element;

        try
        {
            var options = OptionsOf(box, known: null);
            if (options.Count == 0)
            {
                var known = AllOptionKeys();
                options = OpenAndWait(box, known, keyboard: false, openWithKeyboard);
                if (options.Count == 0) options = OpenAndWait(box, known, keyboard: true, openWithKeyboard);
            }

            var target = options.FirstOrDefault(o => isMatch(NameOf(o)));
            if (target != null && Choose(box, target)) return true;

            CloseIfOpen(box, closeWithKeyboard);
            return false;
        }
        catch
        {
            CloseIfOpen(box, closeWithKeyboard);
            return false;
        }
    }

    private List<AutomationElement> OpenAndWait(AutomationElement box, HashSet<string> known,
                                                bool keyboard, Action openWithKeyboard)
    {
        if (keyboard) openWithKeyboard();
        else
        {
            try
            {
                if (!box.TryGetCurrentPattern(ExpandCollapsePattern.Pattern, out var p)) return new();
                ((ExpandCollapsePattern)p).Expand();
            }
            catch { return new(); }
        }

        // The entries are rendered by the page's script once it reacts to the open request.
        for (int waited = 0; waited < 600; waited += 50)
        {
            Thread.Sleep(50);
            var options = OptionsOf(box, known);
            if (options.Count > 0) return options;
        }
        return new();
    }

    // The list's entries: inside the field itself, or - for script-built lists, which usually draw
    // their entries in a popup elsewhere on the page - the list items that weren't there before
    // the list was opened.
    private List<AutomationElement> OptionsOf(AutomationElement box, HashSet<string>? known)
    {
        var found = new List<AutomationElement>();
        foreach (AutomationElement o in box.FindAll(TreeScope.Descendants, OptionCondition)) found.Add(o);
        if (found.Count > 0 || known == null) return found;

        var root = AutomationElement.FromHandle(_hwnd);
        foreach (AutomationElement o in root.FindAll(TreeScope.Descendants, OptionCondition))
            if (!known.Contains(Key(o))) found.Add(o);
        return found;
    }

    private HashSet<string> AllOptionKeys()
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        var root = AutomationElement.FromHandle(_hwnd);
        foreach (AutomationElement o in root.FindAll(TreeScope.Descendants, OptionCondition)) keys.Add(Key(o));
        return keys;
    }

    private static string Key(AutomationElement e)
    {
        try { return string.Join(",", e.GetRuntimeId()); }
        catch { return ""; }
    }

    private static string NameOf(AutomationElement e)
    {
        try { return e.Current.Name ?? ""; }
        catch { return ""; }
    }

    // Select the entry, then make sure the page took it: a list can accept the selection on the
    // automation side while its script never notices. Selecting is tried before invoking because
    // that is what native lists implement; script-built entries often only react to an invoke.
    private static bool Choose(AutomationElement box, AutomationElement option)
    {
        string name = NameOf(option).Trim();
        if (name.Length == 0) return false;

        if (TryPattern(option, SelectionItemPattern.Pattern, p => ((SelectionItemPattern)p).Select())
            && Confirmed(box, name)) return true;
        return TryPattern(option, InvokePattern.Pattern, p => ((InvokePattern)p).Invoke())
               && Confirmed(box, name);
    }

    private static bool TryPattern(AutomationElement e, AutomationPattern pattern, Action<object> act)
    {
        try
        {
            if (!e.TryGetCurrentPattern(pattern, out var p)) return false;
            act(p);
            return true;
        }
        catch { return false; }
    }

    // The field now shows the chosen entry: as its value (native lists) or as the text inside the
    // closed field (script-built ones). While the list is still open its entries can be part of the
    // field too, so that second check only counts once it has closed.
    private static bool Confirmed(AutomationElement box, string name)
    {
        for (int waited = 0; waited <= 450; waited += 50)
        {
            try
            {
                if (box.TryGetCurrentPattern(ValuePattern.Pattern, out var vp)
                    && string.Equals(((ValuePattern)vp).Current.Value?.Trim(), name, StringComparison.OrdinalIgnoreCase))
                    return true;

                if (!IsExpanded(box))
                {
                    foreach (AutomationElement t in box.FindAll(TreeScope.Descendants, TextCondition))
                        if (string.Equals(NameOf(t).Trim(), name, StringComparison.OrdinalIgnoreCase)) return true;
                }
            }
            catch { }
            Thread.Sleep(50);
        }
        return false;
    }

    private static bool IsExpanded(AutomationElement box)
    {
        try
        {
            return box.TryGetCurrentPattern(ExpandCollapsePattern.Pattern, out var p)
                   && ((ExpandCollapsePattern)p).Current.ExpandCollapseState == ExpandCollapseState.Expanded;
        }
        catch { return false; }
    }

    private static void CloseIfOpen(AutomationElement box, Action closeWithKeyboard)
    {
        if (!IsExpanded(box)) return;
        try { ((ExpandCollapsePattern)box.GetCurrentPattern(ExpandCollapsePattern.Pattern)).Collapse(); }
        catch { }
        Thread.Sleep(50);
        if (IsExpanded(box)) closeWithKeyboard();
    }

    // Aliases this short ("mm", "yy", "nr") only count when they are the entire label. As a partial
    // match they fire far too easily - "Geburtsdatum (DD.MM.YYYY)" contains "mm" and would be read
    // as a card expiry month.
    private const int MinPartialMatchLength = 4;

    // Which group a field belongs to, and how long the matching alias was. An exact label or id
    // match decides immediately; otherwise the longest partial match wins, so a "First name" box
    // maps to FirstName and not to FullName just because the word "name" appears in it. The length
    // is handed back so the caller can weigh this against a custom field of the user's own.
    public static FieldGroup Classify(string label, string id, out int matchLength)
    {
        FieldGroup best = FieldGroup.None;
        int bestLen = 0;
        foreach (FieldGroup g in Enum.GetValues<FieldGroup>())
        {
            if (g == FieldGroup.None) continue;
            foreach (string w in FieldAliases.Spellings(g))
            {
                if (label == w || id == w) { matchLength = int.MaxValue; return g; }
                if (w.Length >= MinPartialMatchLength && w.Length > bestLen
                    && !FieldAliases.IsExactOnly(w)
                    && (ContainsWord(label, w) || ContainsWord(id, w)))
                {
                    best = g;
                    bestLen = w.Length;
                }
            }
        }
        matchLength = bestLen;
        return best;
    }

    // Find the field for a group (or, when the group is None, for the literal term the user wrote)
    // and give it the keyboard focus. Returns false if no field matched or the focus didn't take.
    public bool Focus(FieldGroup group, string literalTerm)
    {
        var needles = Needles(group, literalTerm);
        if (needles.Count == 0) return false;

        if (TryFocus(needles)) return true;

        // Nothing matched against the cached tree - the form may have grown since. Rescan once.
        if (_cache != null)
        {
            _cache = null;
            if (TryFocus(needles)) return true;
        }
        return false;
    }

    private bool TryFocus(List<string> needles)
    {
        var list = Cached();
        if (list.Count == 0) return false;

        int start = StartIndex(list);

        // Two passes over the same range: an exact label match wins over a field that merely
        // contains the term, so "Name" doesn't get grabbed by "Name on card" when an exact
        // "Name" field sits further down.
        for (int pass = 0; pass < 2; pass++)
        {
            for (int i = start; i < list.Count; i++)
            {
                var c = list[i];
                foreach (string needle in needles)
                {
                    bool hit = pass == 0
                        ? c.Label == needle || c.Id == needle
                        : ContainsWord(c.Label, needle) || ContainsWord(c.Id, needle);
                    if (hit) return SetFocus(c);
                }
            }
        }
        return false;
    }

    // Where to start looking: at the field that currently has the caret, inclusive. Starting after
    // it would skip the very field the user clicked into before triggering auto-type.
    private int StartIndex(List<Candidate> list)
    {
        int[]? focused = null;
        try { focused = AutomationElement.FocusedElement?.GetRuntimeId(); }
        catch { /* nothing focused, or UIA refused - fall back to the top of the form */ }
        if (focused == null) return 0;

        for (int i = 0; i < list.Count; i++)
            if (SameElement(list[i].RuntimeId, focused)) return i;
        return 0;
    }

    private bool SetFocus(Candidate c)
    {
        if (Native.GetForegroundWindow() != _hwnd) return false;
        try { c.Element.SetFocus(); }
        catch { return false; }

        // Focus changes are asynchronous; confirm the caret really landed on the element we
        // picked before any keystroke goes out.
        for (int waited = 0; waited < 300; waited += 15)
        {
            try
            {
                var now = AutomationElement.FocusedElement?.GetRuntimeId();
                if (now != null && SameElement(c.RuntimeId, now))
                    return Native.GetForegroundWindow() == _hwnd;
            }
            catch { }
            Thread.Sleep(15);
        }
        return false;
    }

    private static List<string> Needles(FieldGroup group, string literalTerm)
    {
        var needles = new List<string>();
        if (group != FieldGroup.None)
            needles.AddRange(FieldAliases.Spellings(group));
        else
        {
            string t = FieldAliases.Normalize(literalTerm);
            if (t.Length > 0) needles.Add(t);
        }
        return needles;
    }

    // Walk the window's automation tree once and keep every enabled, on-screen input field with
    // its label and programmatic id. Both are pulled from a single cached request - reading them
    // one by one would mean a cross-process call per property per element.
    private List<Candidate> Scan()
    {
        var result = new List<Candidate>();
        try
        {
            var root = AutomationElement.FromHandle(_hwnd);
            if (root == null) return result;

            var cache = new CacheRequest();
            cache.Add(AutomationElement.NameProperty);
            cache.Add(AutomationElement.AutomationIdProperty);
            cache.Add(AutomationElement.IsOffscreenProperty);
            cache.Add(AutomationElement.IsEnabledProperty);
            cache.Add(AutomationElement.IsRequiredForFormProperty);
            cache.Add(AutomationElement.RuntimeIdProperty);
            cache.Add(AutomationElement.BoundingRectangleProperty);
            cache.Add(AutomationElement.FrameworkIdProperty);
            cache.Add(AutomationElement.ControlTypeProperty);
            cache.TreeScope = TreeScope.Element | TreeScope.Descendants;

            var cond = new OrCondition(
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Edit),
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.ComboBox));

            System.Windows.Rect window;
            try { window = root.Current.BoundingRectangle; }
            catch { window = System.Windows.Rect.Empty; }

            using (cache.Activate())
            {
                var found = root.FindAll(TreeScope.Descendants, cond);
                foreach (AutomationElement e in found)
                {
                    if (result.Count >= MaxCandidates) break;
                    try
                    {
                        if (!e.Cached.IsEnabled) continue;
                        if (e.Cached.IsOffscreen && !ScrolledOutOfView(e, window)) continue;
                        string rawLabel = e.Cached.Name ?? "";
                        result.Add(new Candidate
                        {
                            Element = e,
                            Label = FieldAliases.Normalize(rawLabel),
                            Id = FieldAliases.Normalize(e.Cached.AutomationId ?? ""),
                            // Forms that use the required attribute say so through UIA. Plenty of
                            // shops only validate in JavaScript and mark mandatory fields with an
                            // asterisk in the label instead, so both count.
                            Required = IsRequired(e) || rawLabel.Contains('*'),
                            IsChoice = e.Cached.ControlType == ControlType.ComboBox,
                            RuntimeId = (int[]?)e.GetCachedPropertyValue(AutomationElement.RuntimeIdProperty)
                                        ?? Array.Empty<int>(),
                        });
                    }
                    catch { /* element vanished mid-walk - skip it */ }
                }
            }
        }
        catch { /* UIA unavailable, window gone, or the app exposes nothing */ }
        return result;
    }

    // A browser field that is only offscreen because it sits further down the page. Anything else
    // stays excluded, in particular the honeypot fields shops park far to the left or above the page
    // to catch bots that fill in everything.
    private static bool ScrolledOutOfView(AutomationElement e, System.Windows.Rect window)
    {
        if (window.IsEmpty || !BrowserFrameworks.Contains(e.Cached.FrameworkId ?? "")) return false;
        var r = e.Cached.BoundingRectangle;
        return !r.IsEmpty && r.Width > 0 && r.Height > 0
               && r.Right > window.Left && r.Left < window.Right
               && r.Top >= window.Top;
    }

    // Not every provider supports IsRequiredForForm; treat an unavailable value as "not required"
    // rather than letting the exception escape the scan.
    private static bool IsRequired(AutomationElement e)
    {
        try { return e.Cached.IsRequiredForForm; }
        catch { return false; }
    }

    // Whole-word containment. Everything is normalised to space-separated words, so padding both
    // sides and doing a plain search is an exact word-boundary test.
    public static bool ContainsWord(string haystack, string needle)
    {
        if (haystack.Length == 0 || needle.Length == 0) return false;
        if (haystack.Length == needle.Length) return haystack == needle;
        return (" " + haystack + " ").Contains(" " + needle + " ", StringComparison.Ordinal);
    }

    private static bool SameElement(int[] a, int[] b)
    {
        if (a.Length == 0 || a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
            if (a[i] != b[i]) return false;
        return true;
    }
}
