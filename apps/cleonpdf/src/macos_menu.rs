//! The macOS menu bar: the app's menus ([`cleonpdf_ui_egui::menu_bar`]) in the system menu bar,
//! where macOS apps keep them, instead of behind the window's Menu button.
//!
//! The menus are built with `muda` (Tauri's menu crate), which wraps the Objective-C a menu
//! needs (a target object for the items' actions), since our workspace forbids `unsafe`. The
//! model is shown every frame: nothing happens while it is unchanged, labels, enablement and
//! checks change in place, and the menus are built again only when items come or go (Open Recent)
//! or another language renames the menus.
//!
//! A chosen item is handed to the app with whether a key press chose it: the system takes a key
//! that matches an item before the window sees it, and the app hands such a choice back to egui
//! as that key (`CleonPdfApp::system_menu_input`).

use std::sync::{Arc, Mutex, PoisonError};

use cleonpdf_engine::commands::Shortcut;
use cleonpdf_ui_egui::menu_bar::{self, Action, Chosen, Entry, EquivalentKey, Mark, Menu, Role, SystemItem, SystemMenu};
use muda::accelerator::{Key, KeyAccelerator, Modifiers, NamedKey};
use muda::{CheckMenuItem, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu};
use objc2::MainThreadMarker;
use objc2_app_kit::{NSApplication, NSControlStateValueOn, NSEventModifierFlags, NSEventType, NSMenu};
use serde_json::{Value, json};

/// One native item, in the order [`MacMenuBar::build`] makes them: each menu, then its entries,
/// a submenu before its own entries.
enum Native {
    Plain(MenuItem),
    Check(CheckMenuItem),
    Submenu(Submenu),
    /// Headings, separators and system items: their text changes only with the language, and
    /// then the menus are built again.
    Fixed,
}

pub struct MacMenuBar {
    /// The menu bar in use (`None` until first shown).
    bar: Option<muda::Menu>,
    /// The menus as last shown.
    shown: Vec<Menu>,
    natives: Vec<Native>,
    /// Each item's action and shortcut; an item's id is its index here.
    actions: Vec<(Action, Option<Shortcut>)>,
    /// Ids chosen since the app last asked, with whether a key press chose them.
    chosen: Arc<Mutex<Vec<(String, bool)>>>,
    /// An item was chosen since the menus were last shown. `muda` flips a check item's mark when
    /// it is clicked, before the app has acted (or refused to), so the marks are set again from
    /// the app's state.
    resync: bool,
}

impl MacMenuBar {
    /// Start listening for choices; the menus appear when first shown. Call on the main thread
    /// (the app creator): `muda` builds its items there.
    pub fn install(ctx: &egui::Context) -> Self {
        let chosen: Arc<Mutex<Vec<(String, bool)>>> = Arc::default();
        let queue = Arc::clone(&chosen);
        let ctx = ctx.clone();
        // Runs on the main thread while AppKit performs the item's action.
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            queue.lock().unwrap_or_else(PoisonError::into_inner).push((event.id.0, chosen_by_key()));
            ctx.request_repaint();
        }));
        Self { bar: None, shown: Vec::new(), natives: Vec::new(), actions: Vec::new(), chosen, resync: false }
    }

    fn build(&mut self, menus: &[Menu]) {
        let bar = muda::Menu::new();
        self.natives.clear();
        self.actions.clear();
        let mut window = None;
        let mut help = None;
        for menu in menus {
            let submenu = Submenu::new(&menu.title, true);
            self.natives.push(Native::Submenu(submenu.clone()));
            self.append(&submenu, &menu.entries);
            if let Err(e) = bar.append(&submenu) {
                log::warn!("menu bar: {} not added: {e}", menu.title);
            }
            match menu.role {
                Role::Window => window = Some(submenu),
                Role::Help => help = Some(submenu),
                _ => {}
            }
        }
        bar.init_for_nsapp();
        // macOS lists the open windows at the Window menu's foot and puts a search field atop Help.
        if let Some(menu) = window {
            menu.set_as_windows_menu_for_nsapp();
        }
        if let Some(menu) = help {
            menu.set_as_help_menu_for_nsapp();
        }
        self.bar = Some(bar);
    }

    fn append(&mut self, parent: &Submenu, entries: &[Entry]) {
        for entry in entries {
            let added = match entry {
                Entry::Item(item) => {
                    let id = MenuId::new(self.actions.len().to_string());
                    self.actions.push((item.action.clone(), item.shortcut));
                    let key = item.shortcut.and_then(accelerator);
                    match item.mark {
                        Mark::Plain => {
                            let native = MenuItem::with_id(id, &item.label, item.enabled, None);
                            if let Err(e) = native.set_key_accelerator(key) {
                                log::warn!("menu bar: no shortcut for {}: {e}", item.label);
                            }
                            let added = parent.append(&native);
                            self.natives.push(Native::Plain(native));
                            added
                        }
                        Mark::Toggle(on) | Mark::Radio(on) => {
                            let native = CheckMenuItem::with_id(id, &item.label, item.enabled, on, None);
                            if let Err(e) = native.set_key_accelerator(key) {
                                log::warn!("menu bar: no shortcut for {}: {e}", item.label);
                            }
                            let added = parent.append(&native);
                            self.natives.push(Native::Check(native));
                            added
                        }
                    }
                }
                Entry::Submenu { title, enabled, entries } => {
                    let submenu = Submenu::new(title, *enabled);
                    self.natives.push(Native::Submenu(submenu.clone()));
                    self.append(&submenu, entries);
                    parent.append(&submenu)
                }
                Entry::Heading(text) => {
                    self.natives.push(Native::Fixed);
                    // Section headers came with macOS 14; before, a disabled item is the title.
                    if objc2::available!(macos = 14.0) {
                        parent.append(&PredefinedMenuItem::section_header(text))
                    } else {
                        parent.append(&MenuItem::new(text, false, None))
                    }
                }
                Entry::Separator => {
                    self.natives.push(Native::Fixed);
                    parent.append(&PredefinedMenuItem::separator())
                }
                Entry::System { item, label } => {
                    self.natives.push(Native::Fixed);
                    let label = Some(label.as_str());
                    parent.append(&match item {
                        SystemItem::Services => PredefinedMenuItem::services(label),
                        SystemItem::Hide => PredefinedMenuItem::hide(label),
                        SystemItem::HideOthers => PredefinedMenuItem::hide_others(label),
                        SystemItem::ShowAll => PredefinedMenuItem::show_all(label),
                        SystemItem::Minimize => PredefinedMenuItem::minimize(label),
                        SystemItem::Zoom => PredefinedMenuItem::maximize(label),
                        SystemItem::BringAllToFront => PredefinedMenuItem::bring_all_to_front(label),
                    })
                }
            };
            if let Err(e) = added {
                log::warn!("menu bar: an item was not added: {e}");
            }
        }
    }

    /// Change labels, enablement and checks in place (same layout as shown). `false` when
    /// something else changed (another language): the menus must be built again.
    fn update(&self, menus: &[Menu]) -> bool {
        let mut natives = self.natives.iter();
        for (old, new) in self.shown.iter().zip(menus) {
            if !matches!(natives.next(), Some(Native::Submenu(_))) || old.title != new.title {
                return false;
            }
            if !update_entries(&mut natives, &old.entries, &new.entries) {
                return false;
            }
        }
        true
    }

    /// Set every check item's mark from `menus`, which have the layout the items were built for.
    fn set_checks(&self, menus: &[Menu]) {
        fn walk<'a>(natives: &mut impl Iterator<Item = &'a Native>, entries: &[Entry]) {
            for entry in entries {
                let Some(native) = natives.next() else { return };
                match (entry, native) {
                    (Entry::Item(item), Native::Check(check)) => check.set_checked(checked(item.mark)),
                    (Entry::Submenu { entries, .. }, Native::Submenu(_)) => walk(natives, entries),
                    _ => {}
                }
            }
        }
        let mut natives = self.natives.iter();
        for menu in menus {
            // The menu itself.
            natives.next();
            walk(&mut natives, &menu.entries);
        }
    }
}

fn checked(mark: Mark) -> bool {
    matches!(mark, Mark::Toggle(true) | Mark::Radio(true))
}

fn update_entries<'a>(natives: &mut impl Iterator<Item = &'a Native>, old: &[Entry], new: &[Entry]) -> bool {
    for (old, new) in old.iter().zip(new) {
        let Some(native) = natives.next() else { return false };
        match (old, new, native) {
            (Entry::Item(o), Entry::Item(n), Native::Plain(item)) => {
                if o.label != n.label {
                    item.set_text(&n.label);
                }
                if o.enabled != n.enabled {
                    item.set_enabled(n.enabled);
                }
            }
            (Entry::Item(o), Entry::Item(n), Native::Check(item)) => {
                if o.label != n.label {
                    item.set_text(&n.label);
                }
                if o.enabled != n.enabled {
                    item.set_enabled(n.enabled);
                }
                if o.mark != n.mark {
                    item.set_checked(checked(n.mark));
                }
            }
            (
                Entry::Submenu { title: ot, enabled: oe, entries: oc },
                Entry::Submenu { title: nt, enabled: ne, entries: nc },
                Native::Submenu(menu),
            ) => {
                if ot != nt {
                    menu.set_text(nt);
                }
                if oe != ne {
                    menu.set_enabled(*ne);
                }
                if !update_entries(natives, oc, nc) {
                    return false;
                }
            }
            (Entry::Heading(a), Entry::Heading(b), Native::Fixed) if a == b => {}
            (Entry::Separator, Entry::Separator, Native::Fixed) => {}
            (Entry::System { label: a, .. }, Entry::System { label: b, .. }, Native::Fixed) if a == b => {}
            _ => return false,
        }
    }
    true
}

impl SystemMenu for MacMenuBar {
    fn show(&mut self, menus: &[Menu]) {
        let resync = std::mem::take(&mut self.resync);
        let unchanged = self.bar.is_some() && self.shown == menus;
        let in_place = unchanged || (self.bar.is_some() && menu_bar::same_layout(&self.shown, menus) && self.update(menus));
        if !in_place {
            self.build(menus);
        } else if resync {
            self.set_checks(menus);
        }
        if !unchanged {
            self.shown = menus.to_vec();
        }
    }

    fn take_chosen(&mut self) -> Vec<Chosen> {
        let ids = std::mem::take(&mut *self.chosen.lock().unwrap_or_else(PoisonError::into_inner));
        self.resync |= !ids.is_empty();
        ids.into_iter()
            .filter_map(|(id, by_key)| {
                let (action, shortcut) = self.actions.get(id.parse::<usize>().ok()?)?.clone();
                Some(Chosen { action, shortcut, by_key })
            })
            .collect()
    }

    fn read_back(&self) -> Value {
        let Some(mtm) = MainThreadMarker::new() else { return Value::Null };
        NSApplication::sharedApplication(mtm).mainMenu().map_or(Value::Null, |menu| menu_json(&menu, 0))
    }
}

/// Whether the event AppKit is handling is a key press (an item's shortcut) rather than a click.
fn chosen_by_key() -> bool {
    MainThreadMarker::new()
        .and_then(|mtm| NSApplication::sharedApplication(mtm).currentEvent())
        .is_some_and(|event| event.r#type() == NSEventType::KeyDown)
}

/// `s` as `muda` writes a key equivalent: ⌘ is META, ⌃ CONTROL.
fn accelerator(s: Shortcut) -> Option<KeyAccelerator> {
    let equivalent = menu_bar::key_equivalent(s)?;
    let key = match equivalent.key {
        EquivalentKey::Character(c) => Key::Character(c.to_string()),
        EquivalentKey::Tab => Key::Named(NamedKey::Tab),
        EquivalentKey::ArrowLeft => Key::Named(NamedKey::ArrowLeft),
        EquivalentKey::ArrowRight => Key::Named(NamedKey::ArrowRight),
        EquivalentKey::Delete => Key::Named(NamedKey::Delete),
    };
    let mut mods = Modifiers::empty();
    mods.set(Modifiers::META, equivalent.command);
    mods.set(Modifiers::SHIFT, equivalent.shift);
    mods.set(Modifiers::CONTROL, equivalent.control);
    Some(KeyAccelerator::new(mods, key))
}

/// What a system menu holds, for the control channel (`ui.menu_bar`'s `read_back`).
fn menu_json(menu: &NSMenu, depth: usize) -> Value {
    let items: Vec<Value> = (0..menu.numberOfItems())
        .filter_map(|i| menu.itemAtIndex(i))
        .map(|item| {
            if item.isSeparatorItem() {
                return json!({ "separator": true });
            }
            let mut v = json!({ "title": item.title().to_string(), "enabled": item.isEnabled() });
            let key = item.keyEquivalent().to_string();
            if !key.is_empty() {
                let mask = item.keyEquivalentModifierMask();
                let mut mods = String::new();
                for (flag, sign) in [
                    (NSEventModifierFlags::Control, '⌃'),
                    (NSEventModifierFlags::Option, '⌥'),
                    (NSEventModifierFlags::Shift, '⇧'),
                    (NSEventModifierFlags::Command, '⌘'),
                ] {
                    if mask.contains(flag) {
                        mods.push(sign);
                    }
                }
                v["key"] = json!(format!("{mods}{key}"));
            }
            if item.state() == NSControlStateValueOn {
                v["checked"] = json!(true);
            }
            // The menus are three deep at most; the bound keeps a cycle from recursing forever.
            if depth < 4
                && let Some(submenu) = item.submenu()
            {
                v["items"] = menu_json(&submenu, depth.saturating_add(1));
            }
            v
        })
        .collect();
    Value::Array(items)
}
