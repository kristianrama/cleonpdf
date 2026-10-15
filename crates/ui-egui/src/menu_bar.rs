//! The menu bar as data: each menu's items with their labels, shortcuts, states and the
//! [`Action`] they run.
//!
//! The Menu button draws it with egui ([`show_entries`]). On macOS the desktop app hands the same
//! menus to the system menu bar through a [`SystemMenu`] (`apps/cleonpdf/src/macos_menu.rs`) and
//! the Menu button goes away. Either way a choice runs through [`CleonPdfApp::menu_action`], so
//! the two list the same commands and do the same thing.
//!
//! The system menu bar takes a key press that matches an item's shortcut before the window sees
//! it. Such a choice is handed back to egui as that key press ([`shortcut_events`]), so the
//! keyboard keeps working exactly as without a menu bar: a text field still gets ⌘Z, ⌘A and
//! ⌘C, and a form field still commits before ⌘S saves.

use cleonpdf_engine::commands::{self, Shortcut};

use crate::{CleonPdfApp, RightPanel, canvas::Fit, theme::Tokens, widgets};

/// One top-level menu.
#[derive(Clone, Debug, PartialEq)]
pub struct Menu {
    pub role: Role,
    pub title: String,
    pub entries: Vec<Entry>,
}

/// Which menu it is: macOS gives the app, Window and Help menus their own behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The menu named after the app (macOS only): About, Preferences, Hide, Quit.
    App,
    File,
    Edit,
    View,
    Pages,
    /// macOS lists the open windows at its foot.
    Window,
    /// macOS adds a search field at its top.
    Help,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Entry {
    Item(Item),
    /// A small title over a group of items ("Zoom").
    Heading(String),
    Separator,
    Submenu {
        title: String,
        enabled: bool,
        entries: Vec<Entry>,
    },
    /// An item the system draws and runs itself (macOS's app and Window menus).
    System {
        item: SystemItem,
        label: String,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Item {
    pub action: Action,
    pub label: String,
    pub shortcut: Option<Shortcut>,
    pub enabled: bool,
    pub mark: Mark,
    /// Hover text (the Menu button only): an Open Recent file's full path.
    pub tooltip: Option<String>,
}

/// Whether an item shows a check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    Plain,
    /// A checkbox: an independent on/off setting.
    Toggle(bool),
    /// One choice of several (macOS shows both kinds as a check mark).
    Radio(bool),
}

/// What choosing an item does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// A registered command (`cleonpdf_engine::commands`).
    Command(&'static str),
    /// A change to the document view that isn't a registered command.
    View(ViewStep),
    /// Show a side panel.
    Panel(RightPanel),
    /// Open a file from File ▸ Open Recent (its path).
    OpenRecent(String),
    /// Cut, Copy, Paste and Select all act on whatever has the keyboard.
    Edit(EditStep),
    /// Quit, asking about unsaved changes first (macOS's app menu).
    Quit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewStep {
    ActualSize,
    PageLevel,
    FitWidth,
    FitHeight,
    ZoomIn,
    ZoomOut,
    RotateClockwise,
    RotateCounterclockwise,
    PreviousView,
    NextView,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditStep {
    Cut,
    Copy,
    Paste,
    SelectAll,
}

/// The macOS items the system provides (and translates the action of, but not the label).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemItem {
    Services,
    Hide,
    HideOthers,
    ShowAll,
    Minimize,
    Zoom,
    BringAllToFront,
}

/// Which menu bar to describe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// The Menu button's: File, Edit, Pages, View, Help.
    InApp,
    /// macOS's: the app menu, File, Edit (with Cut, Copy, Paste and Select all), View, Pages,
    /// Window, Help. `typing` is whether a text field has the keyboard: Undo and Redo are then
    /// its own.
    System { typing: bool },
}

/// An item chosen in the system menu bar.
#[derive(Clone, Debug, PartialEq)]
pub struct Chosen {
    pub action: Action,
    /// The item's shortcut, as shown in the menu.
    pub shortcut: Option<Shortcut>,
    /// Chosen by pressing its shortcut rather than with the pointer.
    pub by_key: bool,
}

/// A menu bar the operating system draws (macOS), fed every frame.
pub trait SystemMenu {
    /// Show `menus`. Called every frame, so it should do nothing when they haven't changed.
    fn show(&mut self, menus: &[Menu]);
    /// The items chosen since the last call, oldest first.
    fn take_chosen(&mut self) -> Vec<Chosen>;
    /// What the system's menu bar holds, read back from the system (the control channel's
    /// `ui.menu_bar`).
    fn read_back(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
}

/// The shortcuts the document view handles itself (`canvas::shortcuts`) for its View items.
fn view_shortcut(step: ViewStep) -> Option<Shortcut> {
    use crate::commands::{ACTUAL_SIZE, FIT_WIDTH, NEXT_VIEW, PAGE_LEVEL, PREV_VIEW, ROTATE_CCW, ROTATE_CW, ZOOM_IN, ZOOM_OUT};
    match step {
        ViewStep::ActualSize => Some(ACTUAL_SIZE),
        ViewStep::PageLevel => Some(PAGE_LEVEL),
        ViewStep::FitWidth => Some(FIT_WIDTH),
        ViewStep::FitHeight => None,
        ViewStep::ZoomIn => Some(ZOOM_IN),
        ViewStep::ZoomOut => Some(ZOOM_OUT),
        ViewStep::RotateClockwise => Some(ROTATE_CW),
        ViewStep::RotateCounterclockwise => Some(ROTATE_CCW),
        ViewStep::PreviousView => Some(PREV_VIEW),
        ViewStep::NextView => Some(NEXT_VIEW),
    }
}

const QUIT: Shortcut = Shortcut::cmd("Q");

fn edit_shortcut(step: EditStep) -> Shortcut {
    match step {
        EditStep::Cut => Shortcut::cmd("X"),
        EditStep::Copy => crate::commands::COPY,
        EditStep::Paste => Shortcut::cmd("V"),
        EditStep::SelectAll => crate::commands::SELECT_ALL,
    }
}

fn item(action: Action, label: impl Into<String>, shortcut: Option<Shortcut>, enabled: bool) -> Entry {
    Entry::Item(Item { action, label: label.into(), shortcut, enabled, mark: Mark::Plain, tooltip: None })
}

fn marked(action: Action, label: impl Into<String>, enabled: bool, mark: Mark) -> Entry {
    Entry::Item(Item { action, label: label.into(), shortcut: None, enabled, mark, tooltip: None })
}

fn system(item: SystemItem, label: &str) -> Entry {
    Entry::System { item, label: label.to_owned() }
}

impl CleonPdfApp {
    /// The menus for `target`. Without a document the View menu's zoom and page items are left
    /// out of the Menu button's and disabled in the system's, which keeps its items in place.
    pub fn menu_bar(&self, target: Target) -> Vec<Menu> {
        let system_bar = matches!(target, Target::System { .. });
        let typing = matches!(target, Target::System { typing: true });
        // Under a dialog nothing may act on the document (as `shortcuts` refuses its keys).
        // Cut, Copy, Paste and Select all stay: they act on the dialog's own fields.
        let blocked = self.modal_open();
        let file = self.registry_entries("File", blocked, typing);
        let mut edit = self.registry_entries("Edit", blocked, typing);
        let pages = self.registry_entries("Pages", blocked, typing);
        let mut help = self.registry_entries("Help", blocked, typing);
        let view = self.view_entries(system_bar, blocked, typing);
        if !system_bar {
            return vec![
                Menu { role: Role::File, title: tl!("File").into(), entries: file },
                Menu { role: Role::Edit, title: tl!("Edit").into(), entries: edit },
                Menu { role: Role::Pages, title: tl!("Pages").into(), entries: pages },
                Menu { role: Role::View, title: tl!("View").into(), entries: view },
                Menu { role: Role::Help, title: tl!("Help").into(), entries: help },
            ];
        }
        // macOS keeps About, Check for updates and Preferences in the app menu.
        fn take(entries: &mut Vec<Entry>, id: &str) -> Option<Entry> {
            let at = entries.iter().position(|e| matches!(e, Entry::Item(Item { action: Action::Command(c), .. }) if *c == id))?;
            Some(entries.remove(at))
        }
        let about = take(&mut help, "help.about");
        let updates = take(&mut help, "help.check_updates");
        let preferences = take(&mut edit, "app.preferences");
        let mut app = Vec::new();
        for group in [about, updates, preferences].into_iter().flatten() {
            app.push(group);
            app.push(Entry::Separator);
        }
        app.extend([
            system(SystemItem::Services, tl!("Services")),
            Entry::Separator,
            system(SystemItem::Hide, tl!("Hide CleonPDF")),
            system(SystemItem::HideOthers, tl!("Hide others")),
            system(SystemItem::ShowAll, tl_ctx!("app menu", "Show all")),
            Entry::Separator,
            item(Action::Quit, tl!("Quit CleonPDF"), Some(QUIT), true),
        ]);
        // Cut, Copy, Paste and Select all after Undo and Redo, as in every macOS app.
        let after_redo = edit
            .iter()
            .position(|e| matches!(e, Entry::Item(Item { action: Action::Command("edit.redo"), .. })))
            .map_or(0, |at| at.saturating_add(1));
        let clipboard =
            [(EditStep::Cut, tl!("Cut")), (EditStep::Copy, tl!("Copy")), (EditStep::Paste, tl!("Paste")), (EditStep::SelectAll, tl!("Select all"))]
                .into_iter()
                .map(|(step, label)| item(Action::Edit(step), label, Some(edit_shortcut(step)), true));
        let mut group = vec![Entry::Separator];
        group.extend(clipboard);
        group.push(Entry::Separator);
        edit.splice(after_redo..after_redo, group);
        let window = vec![
            system(SystemItem::Minimize, tl!("Minimize")),
            system(SystemItem::Zoom, tl_ctx!("window", "Zoom")),
            Entry::Separator,
            system(SystemItem::BringAllToFront, tl!("Bring all to front")),
        ];
        vec![
            Menu { role: Role::App, title: "CleonPDF".into(), entries: app },
            Menu { role: Role::File, title: tl!("File").into(), entries: file },
            Menu { role: Role::Edit, title: tl!("Edit").into(), entries: edit },
            Menu { role: Role::View, title: tl!("View").into(), entries: view },
            Menu { role: Role::Pages, title: tl!("Pages").into(), entries: pages },
            Menu { role: Role::Window, title: tl!("Window").into(), entries: window },
            Menu { role: Role::Help, title: tl!("Help").into(), entries: help },
        ]
    }

    /// A top-level menu's registered commands, with live labels ("Undo Rotate page"), shortcuts
    /// and enablement. File ▸ Open Recent is the list of recent files.
    fn registry_entries(&self, menu: &str, blocked: bool, typing: bool) -> Vec<Entry> {
        let active = self.active_ids().map(|(_, id)| id);
        let mut entries = Vec::new();
        for spec in commands::menu(menu) {
            // A text field has the keyboard: Undo and Redo are its own, whatever the document's
            // history says.
            let field_edit = typing && matches!(spec.id, "edit.undo" | "edit.redo");
            let label = if field_edit { spec.label.to_owned() } else { commands::current_label(spec, &self.session, active) };
            let label = crate::i18n::menu_label(spec.id, &label);
            if spec.id == "file.open_recent" {
                entries.push(Entry::Submenu { title: label, enabled: !blocked && !self.recent.is_empty(), entries: self.recent_entries() });
                continue;
            }
            let enabled = !blocked && (field_edit || self.command_enabled(spec));
            entries.push(item(Action::Command(spec.id), label, spec.shortcut, enabled));
        }
        entries
    }

    /// File ▸ Open Recent: each file, then Clear Recent Files. Empty while the list is.
    fn recent_entries(&self) -> Vec<Entry> {
        if self.recent.is_empty() {
            return Vec::new();
        }
        let mut entries: Vec<Entry> = self
            .recent
            .iter()
            .map(|r| {
                Entry::Item(Item {
                    action: Action::OpenRecent(r.path.clone()),
                    label: r.name.clone(),
                    shortcut: None,
                    enabled: true,
                    mark: Mark::Plain,
                    tooltip: Some(r.path.clone()),
                })
            })
            .collect();
        entries.push(Entry::Separator);
        entries.push(item(Action::Command("file.clear_recent"), tl!("Clear Recent Files"), None, true));
        entries
    }

    fn view_entries(&self, system_bar: bool, blocked: bool, typing: bool) -> Vec<Entry> {
        let view = self.active.and_then(|i| self.views.get(i));
        let mut entries = Vec::new();
        if system_bar || view.is_some() {
            let on = !blocked && view.is_some();
            let step = |which: ViewStep, label: &str, enabled: bool| item(Action::View(which), label, view_shortcut(which), on && enabled);
            entries.push(Entry::Heading(tl!("Zoom").into()));
            entries.push(step(ViewStep::ActualSize, tl!("Actual size"), true));
            entries.push(step(ViewStep::PageLevel, tl!("Zoom to page level"), true));
            entries.push(step(ViewStep::FitWidth, tl!("Fit to width"), true));
            entries.push(step(ViewStep::FitHeight, tl!("Fit to height"), true));
            let fit_visible = commands::command("view.fit_visible");
            entries.push(item(Action::Command("view.fit_visible"), tl!("Fit visible"), fit_visible.and_then(|c| c.shortcut), on));
            entries.push(step(ViewStep::ZoomIn, tl!("Zoom in"), true));
            entries.push(step(ViewStep::ZoomOut, tl!("Zoom out"), true));
            entries.push(step(ViewStep::RotateClockwise, tl!("Rotate view clockwise"), true));
            entries.push(step(ViewStep::RotateCounterclockwise, tl!("Rotate view counterclockwise"), true));
            entries.push(Entry::Separator);
            entries.push(Entry::Heading(tl!("Page navigation").into()));
            entries.push(step(ViewStep::PreviousView, tl!("Previous view"), view.is_some_and(|v| !v.back.is_empty())));
            entries.push(step(ViewStep::NextView, tl!("Next view"), view.is_some_and(|v| !v.forward.is_empty())));
            entries.push(Entry::Separator);
            entries.push(Entry::Heading(tl!("Page display").into()));
            for layout in crate::canvas::PageLayout::ORDER {
                entries.push(marked(
                    Action::Command(layout.command()),
                    tl!(layout.label()),
                    on,
                    Mark::Radio(view.is_some_and(|v| v.layout == layout)),
                ));
            }
            entries.push(Entry::Separator);
            entries.push(marked(
                Action::Command("view.continuous"),
                tl!("Continuous scrolling"),
                on,
                Mark::Toggle(view.is_some_and(crate::DocView::continuous)),
            ));
            let cover = view.is_some_and(crate::DocView::cover_applies);
            entries.push(marked(
                Action::Command("view.layout.cover"),
                tl!("Show cover page in two-page view"),
                on && cover,
                Mark::Toggle(view.is_some_and(|v| v.cover)),
            ));
            entries.push(Entry::Separator);
        }
        entries.extend(self.registry_entries("View", blocked, typing));
        let themes = [
            (crate::theme::ThemePreference::System, "view.theme.system", tl!("Use system setting")),
            (crate::theme::ThemePreference::Light, "view.theme.light", tl!("Light gray")),
            (crate::theme::ThemePreference::Dark, "view.theme.dark", tl!("Dark gray")),
        ];
        let mut theme: Vec<Entry> = themes
            .into_iter()
            .map(|(preference, id, label)| marked(Action::Command(id), label, !blocked, Mark::Radio(self.theme_preference == preference)))
            .collect();
        theme.push(Entry::Separator);
        theme.push(item(Action::Command("app.preferences"), tl!("Appearance settings…"), None, !blocked));
        entries.push(Entry::Submenu { title: tl!("Display theme").into(), enabled: true, entries: theme });
        let panels = [
            (RightPanel::Comments, tl!("Comments")),
            (RightPanel::Bookmarks, tl!("Bookmarks")),
            (RightPanel::Pages, tl!("Pages")),
            (RightPanel::Fields, tl!("Fields")),
            (RightPanel::Layers, tl!("Layers")),
            (RightPanel::Attachments, tl!("Attachments")),
            (RightPanel::Signatures, tl!("Signatures")),
            (RightPanel::Accessibility, tl!("Accessibility Checker")),
            (RightPanel::Tags, tl!("Tags")),
            (RightPanel::Search, tl!("Search")),
            (RightPanel::Compare, tl!("Compare")),
        ];
        let panels =
            panels.into_iter().map(|(panel, label)| marked(Action::Panel(panel), label, !blocked, Mark::Radio(self.right == Some(panel)))).collect();
        entries.push(Entry::Submenu { title: tl!("Side panels").into(), enabled: true, entries: panels });
        entries
    }

    /// Run a menu item chosen with the pointer (the Menu button's, or the system menu bar's).
    pub fn menu_action(&mut self, ctx: &egui::Context, action: &Action) {
        match action {
            Action::Command(id) => {
                self.execute(id);
            }
            Action::View(step) => {
                let Some(v) = self.active.and_then(|i| self.views.get_mut(i)) else { return };
                match step {
                    ViewStep::ActualSize => v.set_zoom(1.0),
                    ViewStep::PageLevel => v.fit = Fit::Page,
                    ViewStep::FitWidth => v.fit = Fit::Width,
                    ViewStep::FitHeight => {
                        v.fit = Fit::Height;
                        v.goto = Some((v.current, 0.0));
                    }
                    ViewStep::ZoomIn => v.zoom_step(true),
                    ViewStep::ZoomOut => v.zoom_step(false),
                    ViewStep::RotateClockwise => v.rotate_view(true),
                    ViewStep::RotateCounterclockwise => v.rotate_view(false),
                    ViewStep::PreviousView => {
                        v.view_history(false);
                    }
                    ViewStep::NextView => {
                        v.view_history(true);
                    }
                }
            }
            Action::Panel(panel) => self.choose_right_panel(Some(*panel)),
            Action::OpenRecent(path) => self.open_recent(path),
            // The Menu button has none of these; the system menu bar's go through
            // `system_menu_input`, which hands them to whatever has the keyboard.
            Action::Edit(EditStep::Cut) => ctx.send_viewport_cmd(egui::ViewportCommand::RequestCut),
            Action::Edit(EditStep::Copy) => ctx.send_viewport_cmd(egui::ViewportCommand::RequestCopy),
            Action::Edit(EditStep::Paste) => ctx.send_viewport_cmd(egui::ViewportCommand::RequestPaste),
            Action::Edit(EditStep::SelectAll) => {
                if let Some(i) = self.active {
                    self.select_all_in_document(i);
                }
            }
            // Like closing the window: `guard_quit` asks about unsaved changes.
            Action::Quit => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
        }
    }

    /// Before egui reads this frame's input: the items chosen in the system menu bar since the
    /// last frame. Those that act on whatever has the keyboard become the input they stand for;
    /// the others run in `logic` ([`Self::run_system_choices`]).
    pub(crate) fn system_menu_input(&mut self, ctx: &egui::Context, raw: &mut egui::RawInput) {
        let Some(menu) = self.system_menu.as_mut() else { return };
        let chosen = menu.take_chosen();
        if chosen.is_empty() {
            return;
        }
        let typing = ctx.text_edit_focused();
        for c in chosen {
            let replay = match &c.action {
                Action::Quit => None,
                // Cut, Copy, Paste and Select all, however chosen, are the keys they stand for.
                Action::Edit(step) => Some(edit_shortcut(*step)),
                // Its own key, pressed: handled as if no menu bar had taken it.
                _ if c.by_key => c.shortcut,
                // Undo and Redo chosen with the pointer while a text field has the keyboard.
                Action::Command(id @ ("edit.undo" | "edit.redo")) if typing => commands::command(id).and_then(|spec| spec.shortcut),
                _ => None,
            };
            match replay {
                Some(s) if s == Shortcut::cmd("V") => ctx.send_viewport_cmd(egui::ViewportCommand::RequestPaste),
                Some(s) => raw.events.extend(shortcut_events(s)),
                None => self.system_choices.push(c.action),
            }
        }
        ctx.request_repaint();
    }

    /// Run the system menu bar's pointer choices (`logic`, before this frame's shortcuts). A
    /// command chosen while a form field's editor is open waits a frame, as its shortcut does, so
    /// the field's typing is in the document first.
    pub(crate) fn run_system_choices(&mut self, ctx: &egui::Context) {
        let form_typing = self.active.and_then(|i| self.views.get(i)).is_some_and(|v| v.forms.focus.is_some());
        for action in std::mem::take(&mut self.system_choices) {
            // A dialog opened since the menu was last drawn.
            if self.modal_open() && action != Action::Quit {
                continue;
            }
            match action {
                Action::Command(id) if form_typing => {
                    self.deferred_commands.push((id, self.active_ids().map(|(_, doc)| doc)));
                    ctx.request_repaint();
                }
                other => self.menu_action(ctx, &other),
            }
        }
    }

    /// Show this frame's state in the system menu bar, if there is one.
    pub(crate) fn sync_system_menu(&mut self, ctx: &egui::Context) {
        if self.system_menu.is_none() {
            return;
        }
        let menus = self.menu_bar(Target::System { typing: ctx.text_edit_focused() });
        if let Some(menu) = self.system_menu.as_mut() {
            menu.show(&menus);
        }
    }

    /// The menu bar for the control channel's `ui.menu_bar`: the system's when there is one.
    pub(crate) fn menu_bar_json(&self, ctx: &egui::Context) -> serde_json::Value {
        let system = self.system_menu.as_ref();
        let target = if system.is_some() { Target::System { typing: ctx.text_edit_focused() } } else { Target::InApp };
        let menus: Vec<serde_json::Value> = self.menu_bar(target).iter().map(menu_json).collect();
        serde_json::json!({
            "system": system.is_some(),
            "menus": menus,
            "read_back": system.map_or(serde_json::Value::Null, |m| m.read_back()),
        })
    }
}

fn menu_json(menu: &Menu) -> serde_json::Value {
    serde_json::json!({ "title": menu.title, "items": entries_json(&menu.entries) })
}

fn entries_json(entries: &[Entry]) -> Vec<serde_json::Value> {
    entries
        .iter()
        .map(|e| match e {
            Entry::Item(i) => {
                let mut v = serde_json::json!({ "label": i.label, "enabled": i.enabled });
                if let Some(s) = i.shortcut {
                    v["shortcut"] = s.label(true).into();
                }
                match i.mark {
                    Mark::Plain => {}
                    Mark::Toggle(on) | Mark::Radio(on) => v["checked"] = on.into(),
                }
                v
            }
            Entry::Heading(text) => serde_json::json!({ "heading": text }),
            Entry::Separator => serde_json::json!({ "separator": true }),
            Entry::Submenu { title, enabled, entries } => serde_json::json!({ "label": title, "enabled": enabled, "items": entries_json(entries) }),
            Entry::System { label, .. } => serde_json::json!({ "label": label, "system": true }),
        })
        .collect()
}

/// Whether `a` and `b` have the same items in the same places, with the same actions, shortcuts
/// and kinds of mark: then only labels, enablement and checks differ, which a system menu bar can
/// change in place instead of building its menus again.
pub fn same_layout(a: &[Menu], b: &[Menu]) -> bool {
    fn entries(a: &[Entry], b: &[Entry]) -> bool {
        a.len() == b.len()
            && a.iter().zip(b).all(|pair| match pair {
                (Entry::Item(x), Entry::Item(y)) => {
                    x.action == y.action && x.shortcut == y.shortcut && std::mem::discriminant(&x.mark) == std::mem::discriminant(&y.mark)
                }
                (Entry::Heading(_), Entry::Heading(_)) | (Entry::Separator, Entry::Separator) => true,
                (Entry::Submenu { entries: x, .. }, Entry::Submenu { entries: y, .. }) => entries(x, y),
                (Entry::System { item: x, .. }, Entry::System { item: y, .. }) => x == y,
                _ => false,
            })
    }
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.role == y.role && entries(&x.entries, &y.entries))
}

/// The input egui would have had for `s` had no menu bar taken the key: Cut and Copy as the
/// events egui-winit makes of ⌘X and ⌘C, everything else as the key, pressed and released. Paste
/// needs the clipboard's text, which egui-winit fetches on `ViewportCommand::RequestPaste`.
pub fn shortcut_events(s: Shortcut) -> Vec<egui::Event> {
    let plain_command = s.command && !s.shift && !s.mac_ctrl;
    if plain_command && s.key == "X" {
        return vec![egui::Event::Cut];
    }
    if plain_command && s.key == "C" {
        return vec![egui::Event::Copy];
    }
    let Some(key) = egui_key(s.key) else { return Vec::new() };
    // As egui-winit reports them on macOS: ⌘ is both `mac_cmd` and `command`.
    let modifiers = egui::Modifiers { alt: false, ctrl: s.mac_ctrl, shift: s.shift, mac_cmd: s.command, command: s.command };
    let event = |pressed| egui::Event::Key { key, physical_key: None, pressed, repeat: false, modifiers };
    vec![event(true), event(false)]
}

/// egui's key for a shortcut's key name (the registry's, and the view's own: `−`, `←`, `→`).
fn egui_key(name: &str) -> Option<egui::Key> {
    match name {
        "−" => Some(egui::Key::Minus),
        "←" => Some(egui::Key::ArrowLeft),
        "→" => Some(egui::Key::ArrowRight),
        other => egui::Key::from_name(other),
    }
}

/// How a menu bar writes `s` as a key equivalent: the character it matches and the modifiers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEquivalent {
    pub key: EquivalentKey,
    pub command: bool,
    pub shift: bool,
    pub control: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EquivalentKey {
    /// A printable character, lowercase (Shift is a modifier).
    Character(char),
    Tab,
    ArrowLeft,
    ArrowRight,
    Delete,
}

/// [`KeyEquivalent`] for `s`; `None` for a key name no menu can show.
pub fn key_equivalent(s: Shortcut) -> Option<KeyEquivalent> {
    let key = match s.key {
        "Tab" => EquivalentKey::Tab,
        "←" => EquivalentKey::ArrowLeft,
        "→" => EquivalentKey::ArrowRight,
        "Delete" => EquivalentKey::Delete,
        "−" => EquivalentKey::Character('-'),
        other => {
            let mut chars = other.chars();
            let (Some(c), None) = (chars.next(), chars.next()) else { return None };
            EquivalentKey::Character(c.to_lowercase().next().unwrap_or(c))
        }
    };
    Some(KeyEquivalent { key, command: s.command, shift: s.shift, control: s.mac_ctrl })
}

/// Draw `entries` inside an egui menu. Returns the action of the item clicked, if any.
pub(crate) fn show_entries(ui: &mut egui::Ui, entries: &[Entry]) -> Option<Action> {
    let t = Tokens::get(ui.ctx());
    let mut chosen = None;
    for entry in entries {
        match entry {
            Entry::Separator => {
                ui.separator();
            }
            Entry::Heading(text) => {
                ui.label(egui::RichText::new(text).color(t.text_faint).small());
            }
            Entry::System { .. } => {}
            Entry::Submenu { title, enabled, entries } => {
                if *enabled && !entries.is_empty() {
                    ui.menu_button(title, |ui| {
                        if let Some(action) = show_entries(ui, entries) {
                            chosen = Some(action);
                        }
                    });
                } else {
                    ui.add_enabled(false, egui::Button::new(title));
                }
            }
            Entry::Item(item) => {
                let response = match item.mark {
                    Mark::Plain => {
                        let button = egui::Button::new(item.label.as_str());
                        let button = match item.shortcut {
                            Some(s) => button.shortcut_text(crate::commands::shortcut_label(ui.ctx(), s)),
                            None => button,
                        };
                        ui.add_enabled(item.enabled, button)
                    }
                    Mark::Radio(on) => ui.add_enabled(item.enabled, widgets::radio(on, item.label.as_str())),
                    Mark::Toggle(on) => {
                        let mut on = on;
                        ui.add_enabled(item.enabled, widgets::checkbox(&mut on, item.label.as_str()))
                    }
                };
                let response = match &item.tooltip {
                    Some(tip) => response.on_hover_text(tip),
                    None => response,
                };
                if response.clicked() {
                    chosen = Some(item.action.clone());
                    ui.close();
                }
            }
        }
    }
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(entries: &[Entry]) -> Vec<&Item> {
        let mut out = Vec::new();
        for e in entries {
            match e {
                Entry::Item(i) => out.push(i),
                Entry::Submenu { entries, .. } => out.extend(items(entries)),
                _ => {}
            }
        }
        out
    }

    fn all_items(menus: &[Menu]) -> Vec<&Item> {
        menus.iter().flat_map(|m| items(&m.entries)).collect()
    }

    /// A two-page PDF.
    fn fixture() -> Vec<u8> {
        let objects = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 200 300] >>",
            "<< /Type /Page /Parent 2 0 R >>",
            "<< /Type /Page /Parent 2 0 R >>",
        ];
        let mut bytes = b"%PDF-1.7\n".to_vec();
        let mut offsets = Vec::new();
        for (index, object) in objects.iter().enumerate() {
            offsets.push(bytes.len());
            bytes.extend_from_slice(format!("{} 0 obj\n{object}\nendobj\n", index + 1).as_bytes());
        }
        let xref = bytes.len();
        bytes.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes());
        for offset in offsets {
            bytes.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        bytes.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objects.len() + 1).as_bytes());
        bytes
    }

    fn app_with_document() -> CleonPdfApp {
        let mut app = CleonPdfApp::new();
        app.set_option("language", "en").unwrap();
        app.open_bytes("doc.pdf", None, fixture()).unwrap();
        app
    }

    /// Every command the registry puts in a menu is in both menu bars once, with its shortcut.
    #[test]
    fn both_menu_bars_list_every_registered_menu_command_once() {
        let mut app = app_with_document();
        app.recent.push(crate::RecentFile { name: "a.pdf".into(), path: "/x/a.pdf".into(), pages: 1, size: 0 });
        for target in [Target::InApp, Target::System { typing: false }] {
            let menus = app.menu_bar(target);
            let all = all_items(&menus);
            let active = app.active_ids().map(|(_, id)| id);
            for spec in commands::COMMANDS.iter().filter(|c| c.menu.is_some() && c.id != "file.open_recent") {
                // (Display theme ▸ Appearance settings… runs Preferences too, under its own name.)
                let label = crate::i18n::menu_label(spec.id, &commands::current_label(spec, &app.session, active));
                let found: Vec<_> = all.iter().filter(|i| i.action == Action::Command(spec.id) && i.label == label).collect();
                assert_eq!(found.len(), 1, "{target:?}: {} listed {} times", spec.id, found.len());
                assert_eq!(found.first().and_then(|i| i.shortcut), spec.shortcut, "{target:?}: {}'s shortcut", spec.id);
            }
            let shortcuts: Vec<_> = all.iter().filter_map(|i| i.shortcut).collect();
            let unique: std::collections::HashSet<_> = shortcuts.iter().collect();
            assert_eq!(unique.len(), shortcuts.len(), "{target:?}: no shortcut is on two items");
        }
    }

    #[test]
    fn the_system_menu_bar_has_the_mac_menus_in_their_order() {
        let app = app_with_document();
        let roles: Vec<Role> = app.menu_bar(Target::System { typing: false }).iter().map(|m| m.role).collect();
        assert_eq!(roles, [Role::App, Role::File, Role::Edit, Role::View, Role::Pages, Role::Window, Role::Help]);
        let roles: Vec<Role> = app.menu_bar(Target::InApp).iter().map(|m| m.role).collect();
        assert_eq!(roles, [Role::File, Role::Edit, Role::Pages, Role::View, Role::Help], "the Menu button keeps its order");
        let menus = app.menu_bar(Target::System { typing: false });
        let app_menu = items(&menus[0].entries).iter().map(|i| i.action.clone()).collect::<Vec<_>>();
        assert_eq!(
            app_menu,
            [Action::Command("help.about"), Action::Command("help.check_updates"), Action::Command("app.preferences"), Action::Quit],
            "About, Check for updates and Preferences move to the app menu"
        );
        let edit: Vec<Action> = items(&menus[2].entries).iter().map(|i| i.action.clone()).collect();
        assert_eq!(
            edit.get(..6),
            Some(
                &[
                    Action::Command("edit.undo"),
                    Action::Command("edit.redo"),
                    Action::Edit(EditStep::Cut),
                    Action::Edit(EditStep::Copy),
                    Action::Edit(EditStep::Paste),
                    Action::Edit(EditStep::SelectAll)
                ][..]
            )
        );
        assert!(
            !items(&app.menu_bar(Target::InApp)[1].entries).iter().any(|i| matches!(i.action, Action::Edit(_))),
            "the Menu button has no clipboard items"
        );
    }

    #[test]
    fn without_a_document_the_system_view_menu_keeps_its_items_disabled() {
        let mut app = CleonPdfApp::new();
        app.set_option("language", "en").unwrap();
        let system = app.menu_bar(Target::System { typing: false });
        let view = items(&system[3].entries);
        let actual = view.iter().find(|i| i.action == Action::View(ViewStep::ActualSize)).expect("Actual size is listed");
        assert!(!actual.enabled);
        let in_app = app.menu_bar(Target::InApp);
        assert!(!items(&in_app[3].entries).iter().any(|i| matches!(i.action, Action::View(_))), "the Menu button leaves them out, as before");
        let with_doc = app_with_document();
        let system = with_doc.menu_bar(Target::System { typing: false });
        assert!(same_layout(&app.menu_bar(Target::System { typing: false }), &system), "opening a document changes states, not the layout");
        let actual = items(&system[3].entries).into_iter().find(|i| i.action == Action::View(ViewStep::ActualSize)).cloned().unwrap();
        assert!(actual.enabled);
        assert_eq!(actual.shortcut, Some(crate::commands::ACTUAL_SIZE));
    }

    /// Undo names the step, unless a text field has the keyboard: then it is the field's.
    #[test]
    fn undo_names_the_step_or_belongs_to_the_text_field() {
        let mut app = app_with_document();
        let undo = |app: &CleonPdfApp, typing| {
            let menus = app.menu_bar(Target::System { typing });
            all_items(&menus).into_iter().find(|i| i.action == Action::Command("edit.undo")).cloned().unwrap()
        };
        assert!(!undo(&app, false).enabled, "nothing to undo yet");
        assert!(undo(&app, true).enabled, "a text field may have something to undo");
        app.apply_edit(cleonpdf_engine::Edit::RotatePages { pages: vec![0], degrees: 90 });
        assert_eq!(undo(&app, false).label, "Undo Rotate page");
        assert_eq!(undo(&app, true).label, "Undo");
        assert!(same_layout(&app.menu_bar(Target::System { typing: true }), &app.menu_bar(Target::System { typing: false })));
    }

    #[test]
    fn a_dialog_disables_everything_but_the_clipboard_and_quit() {
        let mut app = app_with_document();
        app.dialog = Some(crate::Dialog::About);
        let menus = app.menu_bar(Target::System { typing: false });
        for i in all_items(&menus) {
            let free = matches!(i.action, Action::Edit(_) | Action::Quit);
            assert_eq!(i.enabled, free, "{:?} under a dialog", i.action);
        }
    }

    #[test]
    fn the_recent_list_changes_the_layout_and_names_change_it_in_place() {
        let mut app = app_with_document();
        let before = app.menu_bar(Target::System { typing: false });
        app.recent.push(crate::RecentFile { name: "a.pdf".into(), path: "/x/a.pdf".into(), pages: 1, size: 0 });
        let after = app.menu_bar(Target::System { typing: false });
        assert!(!same_layout(&before, &after), "a new recent file is a new item");
        app.set_option("language", "de").unwrap();
        crate::i18n::set_current(crate::i18n::Lang::from_pref(&app.language));
        let german = app.menu_bar(Target::System { typing: false });
        crate::i18n::set_current(crate::i18n::Lang::EN);
        assert_ne!(german, after);
        assert!(same_layout(&after, &german), "another language only renames");
    }

    #[test]
    fn cut_copy_and_select_all_become_what_egui_winit_makes_of_their_keys() {
        assert_eq!(shortcut_events(edit_shortcut(EditStep::Cut)), [egui::Event::Cut]);
        assert_eq!(shortcut_events(edit_shortcut(EditStep::Copy)), [egui::Event::Copy]);
        let mac = egui::Modifiers { mac_cmd: true, command: true, ..Default::default() };
        let key = |key, pressed, modifiers| egui::Event::Key { key, physical_key: None, pressed, repeat: false, modifiers };
        assert_eq!(shortcut_events(edit_shortcut(EditStep::SelectAll)), [key(egui::Key::A, true, mac), key(egui::Key::A, false, mac)]);
        let shift = egui::Modifiers { shift: true, ..mac };
        assert_eq!(shortcut_events(Shortcut::cmd_shift("Z")), [key(egui::Key::Z, true, shift), key(egui::Key::Z, false, shift)]);
        let ctrl = egui::Modifiers { ctrl: true, ..Default::default() };
        let tab = commands::command("view.next_tab").and_then(|c| c.shortcut).unwrap();
        assert_eq!(shortcut_events(tab), [key(egui::Key::Tab, true, ctrl), key(egui::Key::Tab, false, ctrl)]);
    }

    /// Every shortcut either menu bar shows can be pressed again as an egui key and written as a
    /// key equivalent.
    #[test]
    fn every_shortcut_in_the_menus_has_a_key_and_a_key_equivalent() {
        let mut app = app_with_document();
        app.recent.push(crate::RecentFile { name: "a.pdf".into(), path: "/x/a.pdf".into(), pages: 1, size: 0 });
        for target in [Target::InApp, Target::System { typing: false }] {
            for item in all_items(&app.menu_bar(target)) {
                let Some(s) = item.shortcut else { continue };
                assert!(!shortcut_events(s).is_empty(), "{} has no egui key", s.label(true));
                assert!(key_equivalent(s).is_some(), "{} has no key equivalent", s.label(true));
            }
        }
        let zoom_out = key_equivalent(crate::commands::ZOOM_OUT).unwrap();
        assert_eq!(zoom_out.key, EquivalentKey::Character('-'));
        let save_as = key_equivalent(Shortcut::cmd_shift("S")).unwrap();
        assert_eq!(save_as, KeyEquivalent { key: EquivalentKey::Character('s'), command: true, shift: true, control: false });
        let read_mode = key_equivalent(commands::command("view.read_mode").and_then(|c| c.shortcut).unwrap()).unwrap();
        assert!(read_mode.control && read_mode.command && !read_mode.shift);
        assert_eq!(key_equivalent(Shortcut::cmd("Tab")).map(|k| k.key), Some(EquivalentKey::Tab));
        assert_eq!(key_equivalent(Shortcut::cmd("Fn")), None, "a multi-letter name that isn't a known key");
    }
}
