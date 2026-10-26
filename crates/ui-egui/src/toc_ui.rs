//! Pages ▸ Link the table of contents: find the table of contents printed in the document, show
//! where each entry leads, let the user correct where printed page 1 is, then make the entries
//! links to their pages and/or bookmarks (one undoable edit). Finding is `cleonpdf_engine::toc`.

use cleonpdf_engine::DocId;
use cleonpdf_engine::toc::{Mapping, Toc};
use egui::{Align, Layout};

use crate::theme::{self, Tokens};
use crate::{CleonPdfApp, Dialog, widgets};

/// The dialog's state: the table of contents found and the choices.
#[derive(Clone, Debug, PartialEq)]
pub struct TocDraft {
    pub doc: DocId,
    pub toc: Toc,
    /// Make the entries links.
    pub links: bool,
    /// Add them as bookmarks.
    pub bookmarks: bool,
    /// The PDF page (1-based) printed page 1 is: what the user corrects.
    pub first_page: i64,
}

impl CleonPdfApp {
    /// Find the table of contents in the active document and open the dialog, or say there is
    /// none.
    pub fn open_link_toc(&mut self) {
        let Some((_, id)) = self.active_ids() else { return };
        let Some(toc) = self.session.find_toc(id) else {
            self.notify_tr("No table of contents was found in this document's text. If it is a scan, recognize its text first.");
            return;
        };
        let doc = self.session.get(id);
        // Bookmarks too, unless the document has its own (or may not get any).
        let bookmarks = doc.is_some_and(|d| d.info.outline.is_empty() && d.allows_assembly());
        let first_page = toc.first_page();
        self.toc_draft = Some(TocDraft { doc: id, toc, links: true, bookmarks, first_page });
        self.dialog = Some(Dialog::LinkToc);
    }

    /// Apply the dialog's choices.
    pub(crate) fn apply_link_toc(&mut self) {
        let Some(d) = self.toc_draft.take() else { return };
        let Some(edit) = self.session.toc_edit(d.doc, &d.toc, d.links, d.bookmarks) else {
            self.notify_tr("The table of contents is already linked");
            return;
        };
        if self.active_ids().map(|(_, id)| id) != Some(d.doc) {
            return;
        }
        if self.apply_edit(edit) {
            match (d.links, d.bookmarks) {
                (true, true) => self.notify_tr("The table of contents is linked and in the bookmarks"),
                (true, false) => self.notify_tr("The table of contents is linked"),
                _ => self.notify_tr("The table of contents is in the bookmarks"),
            }
        }
    }
}

/// The dialog. Returns (apply, cancel).
pub(crate) fn body(ui: &mut egui::Ui, app: &mut CleonPdfApp, t: &Tokens) -> (bool, bool) {
    let assembly = app.active_ids().and_then(|(_, id)| app.session.get(id)).is_some_and(cleonpdf_engine::Document::allows_assembly);
    let Some(d) = app.toc_draft.as_mut() else { return (false, true) };
    ui.label(egui::RichText::new(tl!("Link the table of contents")).font(theme::semibold(18.0)));
    ui.add_space(8.0);
    let count = d.toc.entries.len();
    let linked = d.toc.linked().count();
    ui.label(crate::i18n::fmt(
        tl!("Entries found: {count}. In this file: {linked}."),
        &[("count", &count.to_string()), ("linked", &linked.to_string())],
    ));
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label(tl!("Printed page 1 is PDF page"));
        let pages = i64::try_from(d.toc.pages).unwrap_or(i64::MAX);
        if ui.add(egui::DragValue::new(&mut d.first_page).range(-99_999..=pages.max(1))).changed() {
            d.toc.retarget(d.first_page.saturating_sub(2));
        }
    });
    let how = match d.toc.mapping {
        Mapping::Labels => tl!("Matched through the document's page labels."),
        Mapping::PrintedNumbers => tl!("Matched through the page numbers printed on the pages."),
        Mapping::Headings => tl!("Matched through the headings the entries name."),
        Mapping::Assumed => {
            tl!("No page numbers were found on the pages: check where the first entries lead and correct the number above if needed.")
        }
    };
    ui.label(egui::RichText::new(how).small().color(t.text_muted));
    ui.add_space(8.0);
    egui::Frame::new().fill(t.hover).corner_radius(egui::CornerRadius::same(6)).inner_margin(egui::Margin::same(8)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        egui::ScrollArea::vertical().max_height(300.0).auto_shrink([false, true]).show(ui, |ui| {
            // Compact rows: these are labels, not controls.
            ui.spacing_mut().interact_size.y = 18.0;
            egui::Grid::new("toc-entries").num_columns(3).spacing([18.0, 5.0]).show(ui, |ui| {
                let head = |ui: &mut egui::Ui, text: &str| ui.label(egui::RichText::new(text).small().color(t.text_muted));
                head(ui, tl!("Entry"));
                head(ui, tl!("Printed page"));
                head(ui, tl!("PDF page"));
                ui.end_row();
                for e in &d.toc.entries {
                    let colour = if e.target.is_some() { t.text } else { t.text_muted };
                    ui.horizontal(|ui| {
                        ui.set_max_width(400.0);
                        ui.add_space(14.0 * f32::from(e.level.saturating_sub(1).min(5)));
                        ui.add(egui::Label::new(egui::RichText::new(&e.title).color(colour)).truncate());
                    });
                    ui.label(egui::RichText::new(&e.printed).color(colour));
                    match e.target {
                        Some(page) => ui.label(page.saturating_add(1).to_string()),
                        None => ui.label(egui::RichText::new(tl!("not in this file")).color(t.text_muted)),
                    };
                    ui.end_row();
                }
            });
        });
    });
    ui.add_space(8.0);
    ui.add(widgets::checkbox(&mut d.links, tl!("Make the entries clickable")));
    ui.add_enabled(assembly, widgets::checkbox(&mut d.bookmarks, tl!("Add them as bookmarks")));
    if !assembly {
        d.bookmarks = false;
    }
    ui.add_space(10.0);
    let ready = linked > 0 && (d.links || d.bookmarks);
    let (mut go, mut cancel) = (false, false);
    ui.horizontal(|ui| {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.add_enabled_ui(ready, |ui| widgets::pill_button(ui, tl!("Apply"), true)).inner.clicked() {
                go = true;
            }
            if widgets::pill_button(ui, tl!("Cancel"), false).clicked() {
                cancel = true;
            }
        })
    });
    (go, cancel)
}
