//! Clickable tables of contents: find the table of contents printed in a document's text, and the
//! PDF page each entry points to, so the entries can become links and bookmarks.
//!
//! A table of contents is recognised by its layout, not its language: rows that end with a page
//! number in an aligned column, most of them reached through leader dots ("Title . . . 12"), with
//! numbers that grow down the page. The printed numbers are then matched to PDF pages through the
//! document's page labels when it sets them, otherwise through the numbers printed at the top or
//! foot of its pages, otherwise through the headings the entries name. A document with none of
//! these is taken to number its first page 1, and the caller can correct that ([`Toc::retarget`]).
//!
//! Pure functions over each page's text layer: no OCR (a scan needs Recognize text first) and
//! nothing written here.

use cleonpdf_render::PageText;

/// One page's text, for [`find`].
pub struct PageInput<'a> {
    /// The page's index in the document (pages may be a sample of a long document).
    pub index: usize,
    pub text: &'a PageText,
    /// The page's height in view space (points), to tell its header and footer apart.
    pub height: f32,
}

/// The pages [`find`] should read of a `pages`-page document: all of them up to 400, otherwise
/// the first and last 60 (where tables of contents are) and an even sample of the rest (for the
/// printed page numbers), about 240 in all.
pub fn pages_to_read(pages: usize) -> Vec<usize> {
    const ALL: usize = 400;
    const ENDS: usize = 60;
    if pages <= ALL {
        return (0..pages).collect();
    }
    let middle = ENDS..pages.saturating_sub(ENDS);
    let step = middle.len().div_ceil(120).max(1);
    (0..ENDS).chain(middle.step_by(step)).chain(pages.saturating_sub(ENDS)..pages).collect()
}

/// One entry of the table of contents.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    /// The page the entry is printed on.
    pub page: usize,
    /// Its rows, from the start of the title to the end of the page number (view space, points,
    /// y down): one per printed line.
    pub rects: Vec<[f32; 4]>,
    pub title: String,
    /// 1 for a chapter, 2 for its sections and so on: the parts of its number ("2.3.1" is 3), 1
    /// without a number.
    pub level: u8,
    /// The page number as printed: "85", "xii".
    pub printed: String,
    /// `printed` as a number, when it is one in digits.
    pub number: Option<u32>,
    /// The PDF page it points to (0-based), `None` when that page isn't in this file.
    pub target: Option<usize>,
    /// Where its heading is on that page, a little above it (view space, points from the top),
    /// when it was found there.
    pub top: Option<f32>,
    /// The pages where its heading was found, with that place (see `top`), at most 16.
    pub headings: Vec<(usize, f32)>,
}

impl Entry {
    fn set_target(&mut self, target: Option<usize>) {
        self.target = target;
        self.top = target.and_then(|t| self.headings.iter().find(|(p, _)| *p == t).map(|(_, y)| *y));
    }
}

/// One entry made a link ([`crate::Edit::LinkToc`]).
#[derive(Clone, Debug, PartialEq)]
pub struct TocLink {
    /// The page the entry is printed on.
    pub page: usize,
    /// Its rows, in user space.
    pub rects: Vec<[f64; 4]>,
    /// The page it leads to.
    pub target: usize,
    /// Where on that page, in user space (`None`: its top).
    pub top: Option<f64>,
}

/// How the printed page numbers were matched to PDF pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mapping {
    /// The document's page labels.
    Labels,
    /// The page numbers printed at the top or foot of the pages.
    PrintedNumbers,
    /// The headings the entries name, found on their pages.
    Headings,
    /// No evidence: the first page is page 1.
    Assumed,
}

/// A table of contents found by [`find`].
#[derive(Clone, Debug, PartialEq)]
pub struct Toc {
    pub entries: Vec<Entry>,
    /// The PDF page index of printed page 0: printed page `n` is PDF page `n + offset` (0-based)
    /// wherever no better evidence places it.
    pub offset: i64,
    pub mapping: Mapping,
    /// The document's page count.
    pub pages: usize,
}

impl Toc {
    /// The PDF page (1-based) that printed page 1 is, as the caller shows it.
    pub fn first_page(&self) -> i64 {
        self.offset.saturating_add(2)
    }

    /// Place every entry numbered in digits at `number + offset`, overriding what was found
    /// (the caller's correction). Entries numbered otherwise (roman numerals) keep their target.
    pub fn retarget(&mut self, offset: i64) {
        self.offset = offset;
        for e in &mut self.entries {
            if let Some(n) = e.number {
                e.set_target(shifted(n, offset, self.pages));
            }
        }
    }

    /// The entries that point to a page of this file.
    pub fn linked(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(|e| e.target.is_some())
    }
}

/// Printed page `n` moved by `offset`, if that is a page of a `pages`-page document.
fn shifted(n: u32, offset: i64, pages: usize) -> Option<usize> {
    let index = i64::from(n).checked_add(offset)?;
    usize::try_from(index).ok().filter(|i| *i < pages)
}

/// Find the table of contents in `pages` (each page's text, in page order) of a `page_count`-page
/// document whose page labels are `labels` (empty unless it sets labels other than 1, 2, 3…).
/// `None` when there is none, or none with a text layer.
pub fn find(pages: &[PageInput], labels: &[String], page_count: usize) -> Option<Toc> {
    let rows: Vec<(usize, Vec<Row>)> = pages.iter().map(|p| (p.index, rows(p.text))).collect();
    let mut entries = Vec::new();
    let mut previous: Option<(usize, Align)> = None;
    for (index, page_rows) in &rows {
        // A table of contents runs on to the next page, aligned the same way.
        let continues = previous.filter(|(p, _)| p.saturating_add(1) == *index).map(|(_, align)| align);
        match toc_page(*index, page_rows, continues) {
            Some((found, align)) => {
                entries.extend(found);
                previous = Some((*index, align));
            }
            None => previous = None,
        }
    }
    if entries.is_empty() {
        return None;
    }
    let toc_pages: Vec<usize> = entries.iter().map(|e| e.page).collect();
    // The printed number at the top or foot of each page, outside the table of contents.
    let folios: Vec<(usize, Printed)> = pages
        .iter()
        .zip(&rows)
        .filter(|(p, _)| !toc_pages.contains(&p.index))
        .filter_map(|(p, (_, r))| folio(r, p.height).map(|f| (p.index, f)))
        .collect();
    let index = HeadingIndex::new(&rows, &toc_pages);
    for e in &mut entries {
        e.headings = index.find(e);
    }
    let mut toc = Toc { entries, offset: -1, mapping: Mapping::Assumed, pages: page_count };
    place(&mut toc, labels, &folios, &toc_pages);
    Some(toc)
}

/// Match the entries' printed numbers to PDF pages (see the module comment for the order).
fn place(toc: &mut Toc, labels: &[String], folios: &[(usize, Printed)], toc_pages: &[usize]) {
    let pages = toc.pages;
    // Labels, when most entries name one.
    let by_label = |printed: &str| labels.iter().position(|l| l.trim().eq_ignore_ascii_case(printed)).filter(|i| *i < pages);
    let labelled = toc.entries.iter().filter(|e| by_label(&e.printed).is_some()).count();
    if !labels.is_empty() && labelled.saturating_mul(2) > toc.entries.len() {
        toc.mapping = Mapping::Labels;
        // The offset for a correction: the most common one among the labelled entries.
        let votes: Vec<i64> =
            toc.entries.iter().filter_map(|e| Some(i64::try_from(by_label(&e.printed)?).ok()?.saturating_sub(i64::from(e.number?)))).collect();
        toc.offset = mode(&votes).unwrap_or(-1);
        for e in &mut toc.entries {
            let target = by_label(&e.printed);
            e.set_target(target);
        }
        return;
    }
    // The page numbers printed on the pages.
    let votes: Vec<i64> = folios
        .iter()
        .filter_map(|(i, f)| match f {
            Printed::Arabic(n) => Some(i64::try_from(*i).ok()?.saturating_sub(i64::from(*n))),
            Printed::Roman(_) => None,
        })
        .collect();
    if let Some(offset) = mode(&votes).filter(|o| votes.iter().filter(|v| *v == o).count().saturating_mul(2) >= votes.len() && votes.len() >= 2) {
        toc.mapping = Mapping::PrintedNumbers;
        toc.offset = offset;
        for e in &mut toc.entries {
            let exact = folios.iter().find(|(_, f)| f.text_eq(&e.printed)).map(|(i, _)| *i);
            let target = exact.or_else(|| e.number.and_then(|n| shifted(n, offset, pages)));
            e.set_target(target);
        }
        return;
    }
    // The headings the entries name.
    let votes: Vec<i64> = toc
        .entries
        .iter()
        .filter_map(|e| {
            let n = i64::from(e.number?);
            let page = e.headings.iter().map(|(p, _)| *p).find(|p| !toc_pages.contains(p))?;
            Some(i64::try_from(page).ok()?.saturating_sub(n))
        })
        .collect();
    if let Some(offset) = mode(&votes).filter(|o| votes.iter().filter(|v| *v == o).count() >= 2) {
        toc.mapping = Mapping::Headings;
        toc.retarget(offset);
        return;
    }
    toc.mapping = Mapping::Assumed;
    toc.retarget(-1);
}

/// The most common value (the smallest of those tied).
fn mode(values: &[i64]) -> Option<i64> {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let mut best: Option<(i64, usize)> = None;
    for run in sorted.chunk_by(|a, b| a == b) {
        let (Some(v), n) = (run.first(), run.len()) else { continue };
        if best.is_none_or(|(_, m)| n > m) {
            best = Some((*v, n));
        }
    }
    best.map(|(v, _)| v)
}

/// Every row outside the table of contents by its first word, to find the entries' headings
/// without reading every row once per entry.
struct HeadingIndex {
    /// First word → (page, the row's words, where to land: a line above it).
    rows: std::collections::HashMap<String, Vec<(usize, Vec<String>, f32)>>,
}

impl HeadingIndex {
    fn new(rows: &[(usize, Vec<Row>)], toc_pages: &[usize]) -> Self {
        let mut index: std::collections::HashMap<String, Vec<(usize, Vec<String>, f32)>> = std::collections::HashMap::new();
        for (page, page_rows) in rows.iter().filter(|(i, _)| !toc_pages.contains(i)) {
            for r in page_rows {
                // A heading's start is enough to match; long rows are body text.
                let words: Vec<String> = normalize(&r.text(0, r.glyphs.len())).split_whitespace().take(12).map(fold).collect();
                if let Some(first) = words.first().cloned() {
                    index.entry(first).or_default().push((*page, words, (r.y0 - r.height()).max(0.0)));
                }
            }
        }
        Self { rows: index }
    }

    /// The pages with a row that starts with the entry's heading (its section number and first
    /// word, or its whole title when it has no number), and where: a little above that row. The
    /// first such row on each page, at most 16 pages.
    fn find(&self, e: &Entry) -> Vec<(usize, f32)> {
        let words: Vec<String> = e.title.split_whitespace().map(fold).collect();
        let key: Vec<String> = match words.first() {
            Some(first) if section_depth(first).is_some() => words.iter().take(2).cloned().collect(),
            _ => words.iter().take(12).cloned().collect(),
        };
        if key.iter().map(|w| w.chars().count()).sum::<usize>() < 4 {
            return Vec::new();
        }
        let Some(candidates) = key.first().and_then(|k| self.rows.get(k)) else { return Vec::new() };
        let mut found: Vec<(usize, f32)> = Vec::new();
        for (page, row, top) in candidates {
            let starts = row.len() >= key.len() && row.iter().zip(&key).all(|(a, b)| a == b);
            if starts && !found.iter().any(|(p, _)| p == page) {
                found.push((*page, *top));
                if found.len() >= 16 {
                    break;
                }
            }
        }
        found
    }
}

fn fold(word: &str) -> String {
    cleonpdf_render::text::fold_case(word.trim_matches(|c: char| !c.is_alphanumeric() && c != '.'))
}

// ── Rows ───────────────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Glyph {
    text: String,
    x0: f32,
    y0: f32,
    x1: f32,
    y1: f32,
    /// A word break before it.
    space: bool,
}

/// Glyphs sharing a baseline, left to right. The text layer splits a row whose parts are far
/// apart ("1 Chapter … 7") into lines read one after the other; a row puts them back together.
#[derive(Clone, Debug)]
struct Row {
    glyphs: Vec<Glyph>,
    y0: f32,
    y1: f32,
}

impl Row {
    fn x0(&self) -> f32 {
        self.glyphs.first().map_or(0.0, |g| g.x0)
    }

    /// The typical glyph height.
    fn height(&self) -> f32 {
        let mut h: Vec<f32> = self.glyphs.iter().map(|g| g.y1 - g.y0).filter(|h| h.is_finite() && *h > 0.0).collect();
        h.sort_by(f32::total_cmp);
        h.get(h.len() / 2).copied().unwrap_or(10.0).max(1.0)
    }

    /// The text of glyphs `from..to`, with spaces at word breaks.
    fn text(&self, from: usize, to: usize) -> String {
        let mut s = String::new();
        for (i, g) in self.glyphs.iter().enumerate().take(to).skip(from) {
            if i > from && g.space {
                s.push(' ');
            }
            s.push_str(&g.text);
        }
        s
    }

    fn rect(&self, from: usize, to: usize) -> Option<[f32; 4]> {
        let gs = self.glyphs.get(from..to.min(self.glyphs.len()))?;
        let first = gs.first()?;
        Some(gs.iter().fold([first.x0, first.y0, first.x1, first.y1], |r, g| [r[0].min(g.x0), r[1].min(g.y0), r[2].max(g.x1), r[3].max(g.y1)]))
    }
}

/// The page's rows, top to bottom. Only horizontal, left-to-right text is read.
fn rows(text: &PageText) -> Vec<Row> {
    // The text layer's lines, as runs of glyphs.
    let mut segments: Vec<Vec<Glyph>> = Vec::new();
    let mut current_line = None;
    for (i, g) in text.glyphs.iter().enumerate() {
        let horizontal = g.direction[0] > 0.9 && g.direction[1].abs() < 0.2;
        let [x0, y0, x1, y1] = g.rect;
        if !horizontal || ![x0, y0, x1, y1].iter().all(|v| v.is_finite()) || g.text.trim().is_empty() {
            continue;
        }
        let line = text.line_of.get(i).copied();
        let glyph = Glyph { text: g.text.clone(), x0, y0, x1, y1, space: text.space_before.get(i).copied().unwrap_or(false) };
        match segments.last_mut() {
            Some(seg) if line == current_line => seg.push(glyph),
            _ => {
                current_line = line;
                segments.push(vec![Glyph { space: true, ..glyph }]);
            }
        }
    }
    let centre = |seg: &[Glyph]| {
        let (y0, y1) = seg.iter().fold((f32::MAX, f32::MIN), |(a, b), g| (a.min(g.y0), b.max(g.y1)));
        (y0, y1, (y0 + y1) / 2.0)
    };
    let mut segments: Vec<(f32, f32, f32, Vec<Glyph>)> = segments
        .into_iter()
        .map(|s| {
            let (y0, y1, c) = centre(&s);
            (y0, y1, c, s)
        })
        .collect();
    segments.sort_by(|a, b| a.2.total_cmp(&b.2));
    let mut out: Vec<Row> = Vec::new();
    for (y0, y1, c, seg) in segments {
        let h = (y1 - y0).max(1.0);
        let joins = out.last().is_some_and(|r| {
            let rh = (r.y1 - r.y0).max(1.0);
            (c - (r.y0 + r.y1) / 2.0).abs() <= 0.35 * h.min(rh)
        });
        match out.last_mut() {
            Some(row) if joins => {
                row.glyphs.extend(seg);
                row.y0 = row.y0.min(y0);
                row.y1 = row.y1.max(y1);
            }
            _ => out.push(Row { glyphs: seg, y0, y1 }),
        }
    }
    for row in &mut out {
        row.glyphs.sort_by(|a, b| a.x0.total_cmp(&b.x0));
        // A word break wherever glyphs stand apart, whichever text-layer line they came from.
        let h = row.height();
        let mut prev_x1: Option<f32> = None;
        for g in &mut row.glyphs {
            if let Some(px) = prev_x1 {
                if g.x0 - px > 0.2 * h {
                    g.space = true;
                } else if g.x0 - px < 0.05 * h && g.space && g.x0 >= px {
                    // Kept from the text layer: a real space can be narrow.
                }
            }
            prev_x1 = Some(g.x1);
        }
        if let Some(first) = row.glyphs.first_mut() {
            first.space = false;
        }
    }
    out
}

// ── Entries ────────────────────────────────────────────────────────────────────────────────────

/// A page number as printed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Printed {
    Arabic(u32),
    Roman(u32),
}

impl Printed {
    fn parse(s: &str) -> Option<Self> {
        if !s.is_empty() && s.len() <= 5 && s.bytes().all(|b| b.is_ascii_digit()) {
            return s.parse().ok().map(Printed::Arabic);
        }
        roman(s).map(Printed::Roman)
    }

    /// Whether `printed` (an entry's) names this page number.
    fn text_eq(&self, printed: &str) -> bool {
        Printed::parse(printed) == Some(*self)
    }
}

/// A roman numeral (all lowercase or all uppercase, as written in page numbers) up to 3999.
fn roman(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > 15 || !(s.chars().all(|c| "ivxlcdm".contains(c)) || s.chars().all(|c| "IVXLCDM".contains(c))) {
        return None;
    }
    let value = |c: char| match c.to_ascii_lowercase() {
        'i' => 1,
        'v' => 5,
        'x' => 10,
        'l' => 50,
        'c' => 100,
        'd' => 500,
        _ => 1000,
    };
    let digits: Vec<i64> = s.chars().map(value).collect();
    let mut total = 0i64;
    for (i, d) in digits.iter().enumerate() {
        // A smaller digit before a larger one is taken away ("iv").
        let smaller = digits.get(i + 1).is_some_and(|next| next > d);
        total += if smaller { -d } else { *d };
    }
    let total = u32::try_from(total).ok().filter(|t| (1..4000).contains(t))?;
    // Only the canonical spelling ("iv", not "iiii" or "vx").
    (to_roman(total) == s.to_ascii_lowercase()).then_some(total)
}

fn to_roman(mut n: u32) -> String {
    let mut s = String::new();
    for (v, r) in [
        (1000, "m"),
        (900, "cm"),
        (500, "d"),
        (400, "cd"),
        (100, "c"),
        (90, "xc"),
        (50, "l"),
        (40, "xl"),
        (10, "x"),
        (9, "ix"),
        (5, "v"),
        (4, "iv"),
        (1, "i"),
    ] {
        while n >= v {
            s.push_str(r);
            n -= v;
        }
    }
    s
}

/// A row that ends with a page number after a title.
#[derive(Clone, Debug)]
struct Candidate {
    row: usize,
    /// Glyphs before the leaders.
    title_end: usize,
    printed: String,
    value: Printed,
    leaders: usize,
    /// The number's left and right edges.
    num_x0: f32,
    num_x1: f32,
    /// Straight after a letter, with no space or leaders ("…essi172"): an entry only if it lines
    /// up with the others.
    glued: bool,
    /// Far from the title, without leaders.
    gap: bool,
}

const LEADERS: [&str; 6] = [".", "·", "…", "‧", "_", "⋯"];

fn candidate(row_index: usize, row: &Row) -> Option<Candidate> {
    let gs = &row.glyphs;
    let h = row.height();
    let last = gs.len().checked_sub(1)?;
    let is_digit = |g: &Glyph| g.text.chars().all(|c| c.is_ascii_digit());
    // The trailing number: digits close together, or one roman word.
    let mut start = last;
    if is_digit(gs.get(last)?) {
        while start > 0 {
            let (Some(prev), Some(cur)) = (gs.get(start - 1), gs.get(start)) else { break };
            if !is_digit(prev) || cur.space || cur.x0 - prev.x1 > 0.3 * h {
                break;
            }
            start -= 1;
        }
    } else {
        while start > 0 && !gs.get(start).is_some_and(|g| g.space) {
            start -= 1;
        }
    }
    let printed: String = gs.get(start..=last)?.iter().map(|g| g.text.as_str()).collect();
    let value = Printed::parse(&printed)?;
    if matches!(value, Printed::Roman(_)) && (start == 0 || !gs.get(start).is_some_and(|g| g.space)) {
        return None;
    }
    // Leader dots before it.
    let mut leaders = 0;
    let mut title_end = start;
    while title_end > 0 {
        let Some(g) = gs.get(title_end - 1) else { break };
        if !LEADERS.contains(&g.text.as_str()) {
            break;
        }
        leaders += if g.text == "…" || g.text == "⋯" { 3 } else { 1 };
        title_end -= 1;
    }
    if title_end == 0 {
        return None;
    }
    let before = gs.get(title_end - 1)?;
    let first_digit = gs.get(start)?;
    let gap = first_digit.x0 - gs.get(start.checked_sub(1)?)?.x1;
    let glued = leaders == 0 && !first_digit.space && before.text.chars().last().is_some_and(char::is_alphabetic) && gap < 0.2 * h;
    let far = leaders < 3 && gap >= 1.5 * h;
    if leaders < 3 && !far && !glued {
        return None;
    }
    Some(Candidate { row: row_index, title_end, printed, value, leaders, num_x0: first_digit.x0, num_x1: gs.get(last)?.x1, glued, gap: far })
}

/// How a page's numbers line up: their right edges or their left edges, at `x`.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Align {
    right: bool,
    x: f32,
}

impl Align {
    fn fits(&self, c: &Candidate) -> bool {
        let x = if self.right { c.num_x1 } else { c.num_x0 };
        (x - self.x).abs() <= 3.0
    }
}

fn median(mut v: Vec<f32>) -> Option<f32> {
    v.sort_by(f32::total_cmp);
    v.get(v.len() / 2).copied()
}

/// The entries on page `index`, if it is (part of) a table of contents, and how its numbers line
/// up. `continues`: the previous page was one, aligned so.
fn toc_page(index: usize, rows: &[Row], continues: Option<Align>) -> Option<(Vec<Entry>, Align)> {
    let candidates: Vec<Candidate> = rows.iter().enumerate().filter_map(|(i, r)| candidate(i, r)).collect();
    let strong: Vec<&Candidate> = candidates.iter().filter(|c| c.leaders >= 3).collect();
    let basis: Vec<&Candidate> = if strong.len() >= 2 { strong.clone() } else { candidates.iter().filter(|c| !c.glued).collect() };
    // Right-aligned numbers (the usual), or left-aligned ones: whichever more of them share.
    let align = continues.unwrap_or_else(|| {
        let right = Align { right: true, x: median(basis.iter().map(|c| c.num_x1).collect()).unwrap_or(0.0) };
        let left = Align { right: false, x: median(basis.iter().map(|c| c.num_x0).collect()).unwrap_or(0.0) };
        if candidates.iter().filter(|c| left.fits(c)).count() > candidates.iter().filter(|c| right.fits(c)).count() { left } else { right }
    });
    let aligned: Vec<&Candidate> = candidates.iter().filter(|c| align.fits(c)).collect();
    let with_leaders = aligned.iter().filter(|c| c.leaders >= 3).count();
    let enough = match continues {
        Some(_) => !aligned.is_empty(),
        None => aligned.len() >= 3 && (with_leaders >= 2 || aligned.len() >= 4),
    };
    if !enough {
        return None;
    }
    // A table of contents counts upwards: in digits, and in roman numerals before them.
    let arabic: Vec<u32> = aligned.iter().filter_map(|c| if let Printed::Arabic(n) = c.value { Some(n) } else { None }).collect();
    let roman: Vec<u32> = aligned.iter().filter_map(|c| if let Printed::Roman(n) = c.value { Some(n) } else { None }).collect();
    let falls = |v: &[u32]| v.windows(2).filter(|w| w.get(1) < w.first()).count();
    let vouched = with_leaders >= 2 || continues.is_some();
    // Leader dots vouch for a slip or two (a misprint); a column without them must count up.
    let allowed = if vouched { 1.max(arabic.len() / 8) } else { 0 };
    if falls(&arabic) > allowed || falls(&roman) > allowed {
        return None;
    }
    if !vouched {
        // Numbers far from their rows, without leaders: a table of figures, or formulas numbered
        // in the margin, unless the rows read like titles and the numbers are in digits.
        let titled = aligned
            .iter()
            .filter(|c| {
                let text = rows.get(c.row).map(|r| r.text(0, c.title_end)).unwrap_or_default();
                let first = text.chars().next();
                first.is_some_and(|ch| ch.is_alphanumeric()) && !text.contains('=') && text.chars().filter(|ch| ch.is_alphabetic()).count() >= 3
            })
            .count();
        if aligned.iter().filter(|c| c.gap).count() < 4 || arabic.len() < aligned.len() || titled.saturating_mul(4) < aligned.len().saturating_mul(3)
        {
            return None;
        }
    }
    let mut entries = Vec::new();
    let mut first_entry_seen = continues.is_some();
    // Rows before an entry that it continues (a title wrapped onto two lines).
    let mut pending: Vec<usize> = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let Some(c) = aligned.iter().find(|c| c.row == i) else {
            if first_entry_seen {
                pending.push(i);
            }
            continue;
        };
        first_entry_seen = true;
        // Only the rows straight above it, each indented less than the next (a hanging indent).
        let mut lead: Vec<usize> = Vec::new();
        let mut below = row;
        let mut below_x0 = title_x0(row);
        for &p in pending.iter().rev() {
            let Some(above) = rows.get(p) else { break };
            let h = above.height();
            if below.y0 - above.y1 > h || below_x0 <= above.x0() + 0.5 * h || candidate(p, above).is_some() {
                break;
            }
            lead.push(p);
            below = above;
            below_x0 = above.x0();
        }
        lead.reverse();
        pending.clear();
        let mut title = String::new();
        let mut rects = Vec::new();
        for &p in &lead {
            let Some(r) = rows.get(p) else { continue };
            title = join(&title, &r.text(0, r.glyphs.len()));
            rects.extend(r.rect(0, r.glyphs.len()));
        }
        title = join(&title, &row.text(0, c.title_end));
        rects.extend(row.rect(0, row.glyphs.len()));
        let title = normalize(&title);
        let title = title.trim_end_matches(|ch: char| ch == '.' || ch.is_whitespace()).to_owned();
        if title.is_empty() {
            continue;
        }
        let level = title.split_whitespace().next().and_then(section_depth).unwrap_or(1);
        let number = match c.value {
            Printed::Arabic(n) => Some(n),
            Printed::Roman(_) => None,
        };
        entries.push(Entry { page: index, rects, title, level, printed: c.printed.clone(), number, target: None, top: None, headings: Vec::new() });
    }
    (!entries.is_empty()).then_some((entries, align))
}

/// Where the title starts on an entry's row, past its section number.
fn title_x0(row: &Row) -> f32 {
    let gs = &row.glyphs;
    let first_word_end = gs.iter().enumerate().skip(1).find(|(_, g)| g.space).map_or(gs.len(), |(i, _)| i);
    let first: String = gs.iter().take(first_word_end).map(|g| g.text.as_str()).collect();
    if section_depth(&first).is_some() { gs.get(first_word_end).map_or(row.x0(), |g| g.x0) } else { row.x0() }
}

/// A title's first part and its continuation, unhyphenated ("derivazio-" + "ne" = "derivazione").
fn join(a: &str, b: &str) -> String {
    let a = a.trim_end();
    let b = b.trim_start();
    if a.is_empty() {
        return b.to_owned();
    }
    let mut chars = a.chars().rev();
    let hyphenated = chars.next() == Some('-') && chars.next().is_some_and(char::is_alphabetic) && b.chars().next().is_some_and(char::is_lowercase);
    if hyphenated { format!("{}{b}", a.trim_end_matches('-')) } else { format!("{a} {b}") }
}

/// The depth of a section number: "3" is 1, "2.3.1" is 3, "A.2" is 2; `None` for other words.
fn section_depth(word: &str) -> Option<u8> {
    let w = word.trim_end_matches('.');
    let parts: Vec<&str> = w.split('.').collect();
    let first = parts.first()?;
    let lettered = first.len() == 1 && first.chars().all(|c| c.is_ascii_uppercase()) && parts.len() > 1;
    let numbered = !first.is_empty() && first.len() <= 3 && first.chars().all(|c| c.is_ascii_digit());
    let rest_ok = parts.iter().skip(1).all(|p| !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()));
    ((lettered || numbered) && rest_ok && parts.len() <= 6).then(|| u8::try_from(parts.len()).unwrap_or(6))
}

/// A title as it should read: TeX's separate accents put back on their letters ("Calcolabilit`a"
/// is "Calcolabilità"), ligatures spelled out, spaces collapsed.
pub fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        let accent = match c {
            '`' | '\u{2035}' => Some(0),
            '´' | '\u{2032}' => Some(1),
            '^' | 'ˆ' => Some(2),
            '¨' => Some(3),
            '~' | '˜' => Some(4),
            _ => None,
        };
        if let (Some(kind), Some(&next)) = (accent, chars.peek())
            && let Some(combined) = accented(next, kind)
        {
            out.push(combined);
            chars.next();
            continue;
        }
        match c {
            'ﬀ' => out.push_str("ff"),
            'ﬁ' => out.push_str("fi"),
            'ﬂ' => out.push_str("fl"),
            'ﬃ' => out.push_str("ffi"),
            'ﬄ' => out.push_str("ffl"),
            'ﬅ' | 'ﬆ' => out.push_str("st"),
            c if c.is_whitespace() => {
                if !out.ends_with(' ') && !out.is_empty() {
                    out.push(' ');
                }
            }
            c => out.push(c),
        }
    }
    out.trim_end().to_owned()
}

/// `letter` with an accent: 0 grave, 1 acute, 2 circumflex, 3 diaeresis, 4 tilde.
fn accented(letter: char, kind: usize) -> Option<char> {
    const TABLE: [(char, [char; 5]); 12] = [
        ('a', ['à', 'á', 'â', 'ä', 'ã']),
        ('e', ['è', 'é', 'ê', 'ë', 'ẽ']),
        ('i', ['ì', 'í', 'î', 'ï', 'ĩ']),
        ('ı', ['ì', 'í', 'î', 'ï', 'ĩ']),
        ('o', ['ò', 'ó', 'ô', 'ö', 'õ']),
        ('u', ['ù', 'ú', 'û', 'ü', 'ũ']),
        ('A', ['À', 'Á', 'Â', 'Ä', 'Ã']),
        ('E', ['È', 'É', 'Ê', 'Ë', 'Ẽ']),
        ('I', ['Ì', 'Í', 'Î', 'Ï', 'Ĩ']),
        ('O', ['Ò', 'Ó', 'Ô', 'Ö', 'Õ']),
        ('U', ['Ù', 'Ú', 'Û', 'Ü', 'Ũ']),
        ('n', ['ǹ', 'ń', 'n', 'n', 'ñ']),
    ];
    let (_, forms) = TABLE.iter().find(|(l, _)| *l == letter)?;
    let c = *forms.get(kind)?;
    (c != letter).then_some(c)
}

/// The page number printed at the top or foot of a page: a row of just a number ("12", "- 12 -",
/// "xii"), or a number at either end of the top row (a running head).
fn folio(rows: &[Row], height: f32) -> Option<Printed> {
    let height = if height.is_finite() && height > 0.0 { height } else { return None };
    let alone = |r: &Row| {
        let text = r.text(0, r.glyphs.len());
        let core = text.trim_matches(|c: char| c.is_whitespace() || matches!(c, '-' | '–' | '—' | '|' | '·' | '•'));
        let core = core
            .strip_prefix("Pagina")
            .or_else(|| core.strip_prefix("Page"))
            .or_else(|| core.strip_prefix("Pag."))
            .or_else(|| core.strip_prefix("p."))
            .unwrap_or(core);
        Printed::parse(core.trim())
    };
    let bottom = rows.last().filter(|r| r.y0 > 0.8 * height);
    let top = rows.first().filter(|r| r.y1 < 0.2 * height);
    if let Some(f) = bottom.and_then(alone).or_else(|| top.and_then(alone)) {
        return Some(f);
    }
    // A running head: "12   CHAPTER TITLE" or "SECTION TITLE   13".
    let r = top?;
    let h = r.height();
    let words = words(r);
    let ends = [words.first(), words.last()];
    let [Some(first), Some(last)] = ends else { return None };
    if words.len() < 2 {
        return None;
    }
    let gap_after_first = words.get(1).map_or(0.0, |w| w.1 - first.2);
    let gap_before_last = words.len().checked_sub(2).and_then(|i| words.get(i)).map_or(0.0, |w| last.1 - w.2);
    if gap_after_first > 2.0 * h
        && let Some(p) = Printed::parse(&first.0)
    {
        return Some(p);
    }
    if gap_before_last > 2.0 * h
        && let Some(p) = Printed::parse(&last.0)
    {
        return Some(p);
    }
    None
}

/// A row's words: text, left and right edge.
fn words(r: &Row) -> Vec<(String, f32, f32)> {
    let mut out: Vec<(String, f32, f32)> = Vec::new();
    for g in &r.glyphs {
        match out.last_mut() {
            Some(w) if !g.space => {
                w.0.push_str(&g.text);
                w.2 = g.x1;
            }
            _ => out.push((g.text.clone(), g.x0, g.x1)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cleonpdf_render::TextGlyph;

    type Spec = (f32, f32, String);

    fn at(x: f32, y: f32, text: &str) -> Spec {
        (x, y, text.to_owned())
    }

    /// A page's text from pieces of (x, y, text): every character 6 pt wide and 10 pt tall, a space
    /// in the text a word break. Each piece is one text-layer line, as the text layer makes far-apart
    /// parts of a row separate lines.
    fn page(pieces: &[Spec]) -> PageText {
        let mut glyphs = Vec::new();
        let mut line_of = Vec::new();
        let mut space_before = Vec::new();
        for (line, (x, y, text)) in pieces.iter().enumerate() {
            let mut cx = *x;
            let mut space = false;
            for ch in text.chars() {
                if ch == ' ' {
                    space = true;
                    cx += 6.0;
                    continue;
                }
                glyphs.push(TextGlyph {
                    text: ch.to_string(),
                    rect: [cx, *y, cx + 6.0, y + 10.0],
                    quad: [[cx, y + 10.0], [cx + 6.0, y + 10.0], [cx + 6.0, *y], [cx, *y]],
                    direction: [1.0, 0.0],
                });
                line_of.push(line as u32);
                space_before.push(space);
                space = false;
                cx += 6.0;
            }
        }
        PageText { glyphs, line_of, space_before }
    }

    /// "title . . . ." then the number, its right edge at x = 400.
    fn dotted(x: f32, y: f32, title: &str, n: &str) -> Vec<Spec> {
        let number_x = 400.0 - 6.0 * n.chars().count() as f32;
        let title_end = x + 6.0 * (title.chars().count() as f32 + 1.0);
        let dots = (((number_x - 6.0 - title_end) / 12.0).max(3.0)) as usize;
        vec![(x, y, format!("{title} {}", ". ".repeat(dots).trim_end())), (number_x, y, n.to_owned())]
    }

    /// A row whose number is printed far to the right, without leaders (a chapter).
    fn far(x: f32, y: f32, title: &str, n: &str) -> Vec<Spec> {
        vec![at(x, y, title), at(400.0 - 6.0 * n.chars().count() as f32, y, n)]
    }

    fn input(text: &PageText, index: usize) -> PageInput<'_> {
        PageInput { index, text, height: 800.0 }
    }

    fn folio_page(n: &str) -> PageText {
        page(&[at(60.0, 100.0, "Some body text on the page"), at(60.0, 120.0, "and another line of it"), at(200.0, 760.0, n)])
    }

    fn italian_toc() -> PageText {
        let glued_title = "1.4 Problemi e riduzioni efficienti tra essi21";
        let mut pieces = vec![at(60.0, 80.0, "Indice")];
        pieces.extend(dotted(70.0, 120.0, "Introduzione", "3"));
        pieces.extend(far(60.0, 140.0, "1 Elementi di Calcolabilit`a", "7"));
        pieces.extend(dotted(70.0, 160.0, "1.1 Idea intuitiva di algoritmo", "8"));
        pieces.extend(dotted(70.0, 180.0, "1.2 Macchina di Turing", "9"));
        pieces.push(at(90.0, 200.0, "1.2.1 Derivazioni canoniche e alberi di derivazio-"));
        pieces.extend(dotted(126.0, 213.0, "ne e di sintassi", "12"));
        pieces.extend(dotted(70.0, 226.0, "1.3 Linguaggi FOR e WHILE", "16"));
        // The number runs into the title, without leaders, ending at the column.
        pieces.push(at(400.0 - 6.0 * glued_title.chars().count() as f32, 239.0, glued_title));
        pieces.extend(far(60.0, 260.0, "2 Un capitolo che non c'è", "73"));
        pieces.push(at(200.0, 760.0, "1"));
        page(&pieces)
    }

    #[test]
    fn an_italian_table_of_contents_with_leaders_chapters_and_wrapped_titles() {
        let toc_page = italian_toc();
        // Printed page n is PDF page n + 2 (1-based): the table of contents is printed page 1.
        let pages: Vec<PageText> = (0..40).map(|i| if i == 2 { toc_page.clone() } else { folio_page(&(i as i64 - 1).to_string()) }).collect();
        let inputs: Vec<PageInput> = pages.iter().enumerate().map(|(i, t)| input(t, i)).collect();
        let toc = find(&inputs, &[], 40).expect("a table of contents");
        let got: Vec<(&str, u8, &str, Option<usize>)> =
            toc.entries.iter().map(|e| (e.title.as_str(), e.level, e.printed.as_str(), e.target)).collect();
        assert_eq!(
            got,
            [
                ("Introduzione", 1, "3", Some(4)),
                ("1 Elementi di Calcolabilità", 1, "7", Some(8)),
                ("1.1 Idea intuitiva di algoritmo", 2, "8", Some(9)),
                ("1.2 Macchina di Turing", 2, "9", Some(10)),
                ("1.2.1 Derivazioni canoniche e alberi di derivazione e di sintassi", 3, "12", Some(13)),
                ("1.3 Linguaggi FOR e WHILE", 2, "16", Some(17)),
                ("1.4 Problemi e riduzioni efficienti tra essi", 2, "21", Some(22)),
                ("2 Un capitolo che non c'è", 1, "73", None),
            ]
        );
        assert_eq!(toc.mapping, Mapping::PrintedNumbers);
        assert_eq!(toc.first_page(), 3, "printed page 1 is PDF page 3");
        let wrapped = toc.entries.iter().find(|e| e.printed == "12").unwrap();
        assert_eq!(wrapped.rects.len(), 2, "a wrapped entry is clickable on both its rows");
        let chapter = toc.entries.iter().find(|e| e.printed == "7").unwrap();
        assert!(chapter.rects[0][2] >= 400.0, "the chapter's link reaches its number");
        assert_eq!(toc.linked().count(), 7);
    }

    #[test]
    fn a_correction_moves_every_numbered_entry() {
        let toc_page = italian_toc();
        let inputs = [input(&toc_page, 0)];
        let mut toc = find(&inputs, &[], 30).expect("found without any other page");
        assert_eq!(toc.mapping, Mapping::Assumed);
        assert_eq!(toc.first_page(), 1, "without evidence, page 1 is printed page 1");
        assert_eq!(toc.entries.first().and_then(|e| e.target), Some(2));
        toc.retarget(5);
        assert_eq!(toc.first_page(), 7);
        assert_eq!(toc.entries.first().and_then(|e| e.target), Some(8));
        assert_eq!(toc.entries.iter().find(|e| e.printed == "16").and_then(|e| e.target), Some(21));
        assert_eq!(toc.entries.iter().find(|e| e.printed == "73").and_then(|e| e.target), None, "past the end");
        toc.retarget(-100);
        assert_eq!(toc.linked().count(), 0, "before the start");
        toc.retarget(i64::MAX);
        assert_eq!(toc.linked().count(), 0, "no overflow");
    }

    #[test]
    fn page_labels_place_roman_and_arabic_entries() {
        let mut pieces = Vec::new();
        for (y, title, n) in [(100.0, "Preface", "ix"), (120.0, "1 Start", "1"), (140.0, "2 Next", "5"), (160.0, "Index", "9")] {
            pieces.extend(dotted(60.0, y, title, n));
        }
        let toc_page = page(&pieces);
        let labels = ["i", "ii", "iii", "iv", "v", "vi", "vii", "viii", "ix", "x", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
        let empty = PageText::default();
        let inputs: Vec<PageInput> = (0..labels.len()).map(|i| input(if i == 2 { &toc_page } else { &empty }, i)).collect();
        let labels: Vec<String> = labels.iter().map(|l| (*l).to_owned()).collect();
        let toc = find(&inputs, &labels, labels.len()).unwrap();
        assert_eq!(toc.mapping, Mapping::Labels);
        let targets: Vec<Option<usize>> = toc.entries.iter().map(|e| e.target).collect();
        assert_eq!(targets, [Some(8), Some(10), Some(14), Some(18)]);
        assert_eq!(toc.first_page(), 11);
    }

    #[test]
    fn headings_place_the_entries_when_pages_print_no_numbers() {
        let mut pieces = vec![at(60.0, 100.0, "Contents")];
        for (y, title, n) in [(120.0, "1 Getting started", "1"), (140.0, "2 Going further", "4"), (160.0, "3 Finishing", "7")] {
            pieces.extend(dotted(60.0, y, title, n));
        }
        let toc_page = page(&pieces);
        let body = |heading: &str| page(&[at(60.0, 100.0, heading), at(60.0, 130.0, "Body text follows here")]);
        let plain = page(&[at(60.0, 100.0, "Body text without a heading")]);
        // PDF pages: 0 cover, 1 contents, 2 = printed 1, …
        let pages = [
            plain.clone(),
            toc_page,
            body("1 Getting started"),
            plain.clone(),
            plain.clone(),
            body("2 Going further"),
            plain.clone(),
            plain.clone(),
            body("3 Finishing"),
        ];
        let inputs: Vec<PageInput> = pages.iter().enumerate().map(|(i, t)| input(t, i)).collect();
        let toc = find(&inputs, &[], pages.len()).unwrap();
        assert_eq!(toc.mapping, Mapping::Headings);
        assert_eq!(toc.entries.iter().map(|e| e.target).collect::<Vec<_>>(), [Some(2), Some(5), Some(8)]);
        // Each leads to its heading, a line above it.
        assert_eq!(toc.entries.iter().map(|e| e.top).collect::<Vec<_>>(), [Some(90.0); 3]);
        let mut moved = toc.clone();
        moved.retarget(0);
        assert_eq!(moved.entries.first().map(|e| (e.target, e.top)), Some((Some(1), None)), "no heading there: the top of the page");
    }

    #[test]
    fn ordinary_pages_and_tables_of_numbers_are_not_tables_of_contents() {
        let prose = page(&[
            at(60.0, 100.0, "In 1900 Hilbert asked 23 questions"),
            at(60.0, 120.0, "and by 1931 Godel had answered 2"),
            at(60.0, 140.0, "The price was 12"),
        ]);
        assert!(find(&[input(&prose, 0)], &[], 1).is_none());
        // Right-aligned figures with no leaders, going up and down.
        let mut pieces = Vec::new();
        for (y, name, n) in [(100.0, "Apples", "42"), (120.0, "Pears", "17"), (140.0, "Plums", "95"), (160.0, "Figs", "3"), (180.0, "Kiwis", "60")] {
            pieces.extend(far(60.0, y, name, n));
        }
        assert!(find(&[input(&page(&pieces), 0)], &[], 1).is_none(), "numbers that fall and rise are a table");
        // Formulas numbered in the margin in roman numerals.
        let mut pieces = Vec::new();
        for (y, formula, n) in
            [(100.0, "f1 = λx. x", "III"), (120.0, "f2 = λx. x + 1", "II"), (140.0, "f3 = λx. x2", "III"), (160.0, "f4 = f2(f3(x))", "IV")]
        {
            pieces.extend(far(60.0, y, formula, n));
        }
        assert!(find(&[input(&page(&pieces), 0)], &[], 1).is_none(), "numbered formulas");
        // Without leaders, a column of titles counting up is a table of contents.
        let mut pieces = Vec::new();
        for (y, title, n) in [(100.0, "Introduction", "1"), (120.0, "Methods", "4"), (140.0, "Results", "9"), (160.0, "Discussion", "15")] {
            pieces.extend(far(60.0, y, title, n));
        }
        assert_eq!(find(&[input(&page(&pieces), 0)], &[], 20).map(|t| t.entries.len()), Some(4));
        assert!(find(&[], &[], 0).is_none());
        assert!(find(&[input(&PageText::default(), 0)], &[], 1).is_none(), "a page without text (a scan)");
    }

    #[test]
    fn a_table_of_contents_runs_on_to_the_next_page() {
        let mut first = vec![at(60.0, 80.0, "Contents")];
        for (y, title, n) in [(100.0, "1 One", "1"), (120.0, "2 Two", "3"), (140.0, "3 Three", "5")] {
            first.extend(dotted(60.0, y, title, n));
        }
        let (p1, p2) = (page(&first), page(&dotted(60.0, 100.0, "4 Four", "8")));
        let toc = find(&[input(&p1, 0), input(&p2, 1)], &[], 20).unwrap();
        assert_eq!(toc.entries.iter().map(|e| (e.page, e.printed.as_str())).collect::<Vec<_>>(), [(0, "1"), (0, "3"), (0, "5"), (1, "8")]);
        // On its own, one entry is not a table of contents.
        assert!(find(&[input(&p2, 1)], &[], 20).is_none());
    }

    #[test]
    fn long_documents_are_sampled_short_ones_read_whole() {
        assert_eq!(pages_to_read(0), Vec::<usize>::new());
        assert_eq!(pages_to_read(400), (0..400).collect::<Vec<_>>());
        let long = pages_to_read(5000);
        assert!(long.len() < 260 && long.contains(&0) && long.contains(&59) && long.contains(&4999) && long.contains(&4940));
        assert!(long.windows(2).all(|w| w[0] < w[1]), "in order, each once");
        assert!(pages_to_read(usize::MAX).len() < 260);
    }

    #[test]
    fn folios_titles_and_numbers() {
        assert_eq!(roman("xiv"), Some(14));
        assert_eq!(roman("XIV"), Some(14));
        assert_eq!(roman("iiii"), None, "only the canonical spelling");
        assert_eq!(roman("mix"), Some(1009));
        assert_eq!(roman("Xiv"), None, "one case");
        assert_eq!(roman("did"), None);
        assert_eq!(roman("ix"), Some(9), "a smaller digit first is taken away");
        assert_eq!(roman("mcmxcix"), Some(1999));
        assert_eq!(Printed::parse("123456"), None, "too long for a page number");
        assert_eq!(section_depth("2.3.1"), Some(3));
        assert_eq!(section_depth("A.2"), Some(2));
        assert_eq!(section_depth("A"), None);
        assert_eq!(section_depth("12."), Some(1));
        assert_eq!(section_depth("1990s"), None);
        assert_eq!(normalize("Calcolabilit`a e complessit´a, ﬁni  e  N´e"), "Calcolabilità e complessitá, fini e Né");
        assert_eq!(join("derivazio-", "ne e di"), "derivazione e di");
        assert_eq!(join("non-", "Deterministic"), "non- Deterministic");
        assert_eq!(join("", "solo"), "solo");
        assert_eq!(mode(&[3, 1, 3, 2, 1]), Some(1), "ties go to the smallest");
        assert_eq!(mode(&[]), None);
        let foot = page(&[at(60.0, 100.0, "text"), at(200.0, 760.0, "- 12 -")]);
        assert_eq!(folio(&rows(&foot), 800.0), Some(Printed::Arabic(12)));
        let head = page(&[at(60.0, 40.0, "3.2 MISURE DI COMPLESSITA"), at(382.0, 40.0, "135"), at(60.0, 100.0, "text")]);
        assert_eq!(folio(&rows(&head), 800.0), Some(Printed::Arabic(135)));
        let roman_foot = page(&[at(60.0, 100.0, "text"), at(200.0, 760.0, "xii")]);
        assert_eq!(folio(&rows(&roman_foot), 800.0), Some(Printed::Roman(12)));
        let none = page(&[at(60.0, 100.0, "text 12")]);
        assert_eq!(folio(&rows(&none), 800.0), None);
        assert_eq!(folio(&rows(&foot), f32::NAN), None);
    }

    /// Untrusted geometry: NaN or infinite boxes are skipped, never a panic.
    #[test]
    fn broken_glyph_boxes_are_skipped() {
        let mut t = italian_toc();
        for g in t.glyphs.iter_mut().step_by(3) {
            g.rect = [f32::NAN, f32::INFINITY, 0.0, -0.0];
        }
        let _ = find(&[input(&t, 0)], &[], 3);
        let t = PageText { glyphs: t.glyphs.clone(), line_of: Vec::new(), space_before: Vec::new() };
        let _ = find(&[input(&t, 0)], &[], 3);
    }
}
