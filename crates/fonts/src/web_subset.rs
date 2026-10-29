//! A web-sized subset of a TrueType face that is still a usable font.
//!
//! The Simplified Chinese interface face is 13 MiB, too much for the web build, but the interface
//! only draws the few hundred characters of its catalogs. `build.rs` cuts the face down to those
//! for wasm32 (the upstream licence allows a subset made solely for web delivery, as long as it
//! is not offered as an installable font; the bytes are only ever embedded in the web binary).
//!
//! `subsetter` cuts the glyphs but drops `cmap`, because it is made for PDF embedding; a text
//! engine needs one, so a format 12 `cmap` for the kept characters is added here and the table
//! directory and checksums are rebuilt.
//!
//! This file is compiled both by `build.rs` and, for its tests, by the crate itself.

use skrifa::{FontRef, MetadataProvider};

/// `font` reduced to the glyphs of `chars` (and `.notdef`), with a `cmap` for them. Characters the
/// font lacks, and whitespace and control characters, are skipped.
///
/// # Errors
///
/// A message when `font` is not a TrueType font or the subset cannot be built.
pub fn subset_with_cmap(font: &[u8], chars: &str) -> Result<Vec<u8>, String> {
    let face = FontRef::new(font).map_err(|e| format!("not a font: {e}"))?;
    let charmap = face.charmap();
    let mut wanted: Vec<char> = chars.chars().filter(|c| !c.is_control() && !c.is_whitespace()).collect();
    wanted.sort_unstable();
    wanted.dedup();

    let mut remapper = subsetter::GlyphRemapper::new();
    let mut kept: Vec<(char, u16)> = Vec::new();
    for c in wanted {
        let Some(old) = charmap.map(c).and_then(|g| u16::try_from(g.to_u32()).ok()) else { continue };
        kept.push((c, remapper.remap(old)));
    }
    if kept.is_empty() {
        return Err("the font has none of the characters".into());
    }
    let cut = subsetter::subset(font, 0, &remapper).map_err(|e| format!("subsetting failed: {e:?}"))?;
    add_cmap(&cut, &kept)
}

/// The `cmap` table (format 12, platform 3 encoding 10) for `(char, new glyph)` pairs sorted by
/// character: consecutive characters with consecutive glyphs share a group.
fn cmap_table(kept: &[(char, u16)]) -> Vec<u8> {
    // (first char, last char, glyph of the first char)
    let mut groups: Vec<(u32, u32, u32)> = Vec::new();
    for &(c, glyph) in kept {
        let (c, glyph) = (u32::from(c), u32::from(glyph));
        match groups.last_mut() {
            Some((start, end, first)) if *end + 1 == c && *first + (c - *start) == glyph => *end = c,
            _ => groups.push((c, c, glyph)),
        }
    }
    let subtable_len = 16 + 12 * groups.len();
    let mut table = Vec::with_capacity(12 + subtable_len);
    // Header: version 0, one encoding record (platform 3, encoding 10) whose subtable follows it.
    table.extend_from_slice(&[0, 0, 0, 1, 0, 3, 0, 10]);
    table.extend_from_slice(&12u32.to_be_bytes());
    table.extend_from_slice(&12u16.to_be_bytes());
    table.extend_from_slice(&0u16.to_be_bytes());
    table.extend_from_slice(&u32::try_from(subtable_len).unwrap_or(u32::MAX).to_be_bytes());
    table.extend_from_slice(&0u32.to_be_bytes());
    table.extend_from_slice(&u32::try_from(groups.len()).unwrap_or(u32::MAX).to_be_bytes());
    for (start, end, glyph) in groups {
        table.extend_from_slice(&start.to_be_bytes());
        table.extend_from_slice(&end.to_be_bytes());
        table.extend_from_slice(&glyph.to_be_bytes());
    }
    table
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(data.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

/// The sum of `data` as big-endian 32-bit words, zero-padded (the sfnt table checksum).
fn checksum(data: &[u8]) -> u32 {
    data.chunks(4).fold(0u32, |sum, chunk| {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        sum.wrapping_add(u32::from_be_bytes(word))
    })
}

/// `font` with a `cmap` for `kept` added: the same tables plus the new one, in tag order, with
/// fresh offsets, checksums and `head.checkSumAdjustment`.
fn add_cmap(font: &[u8], kept: &[(char, u16)]) -> Result<Vec<u8>, String> {
    let bad = || "the subset is not a well-formed TrueType font".to_string();
    let count = usize::from(u16_at(font, 4).ok_or_else(bad)?);
    let mut tables: Vec<([u8; 4], Vec<u8>)> = Vec::with_capacity(count + 1);
    for i in 0..count {
        let record = 12 + i * 16;
        let tag: [u8; 4] = font.get(record..record + 4).ok_or_else(bad)?.try_into().map_err(|_| bad())?;
        let offset = usize::try_from(u32_at(font, record + 8).ok_or_else(bad)?).map_err(|_| bad())?;
        let length = usize::try_from(u32_at(font, record + 12).ok_or_else(bad)?).map_err(|_| bad())?;
        let data = font.get(offset..offset.checked_add(length).ok_or_else(bad)?).ok_or_else(bad)?;
        if &tag != b"cmap" {
            tables.push((tag, data.to_vec()));
        }
    }
    tables.push((*b"cmap", cmap_table(kept)));
    tables.sort_by_key(|(tag, _)| *tag);
    let head = tables.iter().position(|(tag, _)| tag == b"head").ok_or_else(|| "the subset has no head table".to_string())?;
    // checkSumAdjustment (offset 8 of head) is summed as zero.
    if let Some((_, data)) = tables.get_mut(head)
        && let Some(slot) = data.get_mut(8..12)
    {
        slot.fill(0);
    }

    let n = u16::try_from(tables.len()).map_err(|_| bad())?;
    let mut entry_selector = 0u16;
    while 1u32 << (entry_selector + 1) <= u32::from(n) {
        entry_selector += 1;
    }
    let search_range = 16u16.checked_shl(u32::from(entry_selector)).ok_or_else(bad)?;
    let mut out = Vec::new();
    out.extend_from_slice(&[0, 1, 0, 0]);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(&search_range.to_be_bytes());
    out.extend_from_slice(&entry_selector.to_be_bytes());
    out.extend_from_slice(&n.saturating_mul(16).saturating_sub(search_range).to_be_bytes());
    let mut offset = 12 + tables.len() * 16;
    for (tag, data) in &tables {
        out.extend_from_slice(tag);
        out.extend_from_slice(&checksum(data).to_be_bytes());
        out.extend_from_slice(&u32::try_from(offset).map_err(|_| bad())?.to_be_bytes());
        out.extend_from_slice(&u32::try_from(data.len()).map_err(|_| bad())?.to_be_bytes());
        offset += data.len().div_ceil(4) * 4;
    }
    let mut head_at = 0;
    for (tag, data) in &tables {
        if tag == b"head" {
            head_at = out.len();
        }
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(4) * 4, 0);
    }
    let adjustment = 0xB1B0_AFBAu32.wrapping_sub(checksum(&out));
    if let Some(slot) = out.get_mut(head_at + 8..head_at + 12) {
        slot.copy_from_slice(&adjustment.to_be_bytes());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// craft-fonts' Simplified Chinese face, when `CRAFT_FONTS_DIR` points at a checkout that has it.
    fn wenkai() -> Option<Vec<u8>> {
        let dir = std::env::var_os("CRAFT_FONTS_DIR")?;
        std::fs::read(std::path::Path::new(&dir).join("fonts/lxgw-wenkai-lite/LXGWWenKaiLite-Regular.ttf")).ok()
    }

    #[test]
    fn consecutive_characters_with_consecutive_glyphs_share_a_group() {
        let table = cmap_table(&[('a', 5), ('b', 6), ('c', 7), ('x', 9)]);
        // 12-byte header, 16-byte subtable header, two 12-byte groups.
        assert_eq!(table.len(), 12 + 16 + 24);
        assert_eq!(u32_at(&table, 12 + 12), Some(2));
        assert_eq!(u32_at(&table, 12 + 16), Some(u32::from('a')));
        assert_eq!(u32_at(&table, 12 + 20), Some(u32::from('c')));
        assert_eq!(u32_at(&table, 12 + 24), Some(5));
        // A glyph jump starts a new group even for the next character.
        assert_eq!(cmap_table(&[('a', 5), ('b', 9)]).len(), 12 + 16 + 24);
    }

    #[test]
    fn checksum_pads_the_last_word_with_zeros() {
        assert_eq!(checksum(&[0, 0, 0, 1, 2]), 1 + 0x0200_0000);
        assert_eq!(checksum(&[]), 0);
    }

    #[test]
    fn what_is_not_a_font_is_an_error_not_a_panic() {
        assert!(subset_with_cmap(b"", "a").is_err());
        assert!(subset_with_cmap(&[0u8; 64], "a").is_err());
        assert!(add_cmap(&[0, 1, 0, 0, 0xff, 0xff], &[]).is_err());
    }

    #[test]
    fn the_subset_draws_the_characters_it_was_cut_for_and_is_far_smaller() {
        let Some(font) = wenkai() else { return };
        let text = "简体中文界面，打开文件。";
        let subset = subset_with_cmap(&font, text).unwrap_or_default();
        assert!(!subset.is_empty());
        assert!(subset.len() < 100_000, "{} bytes", subset.len());
        assert!(subset.len() * 50 < font.len());

        use skrifa::instance::{LocationRef, Size};
        use skrifa::outline::{DrawSettings, OutlinePen};

        /// Every drawing command of an outline, as text.
        #[derive(Default)]
        struct Record(Vec<String>);
        impl OutlinePen for Record {
            fn move_to(&mut self, x: f32, y: f32) {
                self.0.push(format!("M{x} {y}"));
            }
            fn line_to(&mut self, x: f32, y: f32) {
                self.0.push(format!("L{x} {y}"));
            }
            fn quad_to(&mut self, cx: f32, cy: f32, x: f32, y: f32) {
                self.0.push(format!("Q{cx} {cy} {x} {y}"));
            }
            fn curve_to(&mut self, ax: f32, ay: f32, bx: f32, by: f32, x: f32, y: f32) {
                self.0.push(format!("C{ax} {ay} {bx} {by} {x} {y}"));
            }
            fn close(&mut self) {
                self.0.push("Z".into());
            }
        }
        let face = FontRef::new(&subset).expect("the subset parses");
        let original = FontRef::new(&font).expect("the font parses");
        let outline_of = |font: &FontRef, c: char| {
            let glyph = font.charmap().map(c).unwrap_or_else(|| panic!("{c} is not in the font"));
            let mut pen = Record::default();
            let outline = font.outline_glyphs().get(glyph).expect("an outline");
            outline.draw(DrawSettings::unhinted(Size::unscaled(), LocationRef::default()), &mut pen).expect("draws");
            pen.0
        };
        for c in text.chars() {
            let drawn = outline_of(&face, c);
            assert!(drawn.len() > 3, "{c} draws nothing");
            assert_eq!(drawn, outline_of(&original, c), "{c}");
        }
        // What was not asked for is not there.
        assert!(face.charmap().map('们').is_none());
    }

    #[test]
    fn the_web_character_list_cuts_the_real_face_to_a_web_sized_font_with_all_of_them() {
        let Some(font) = wenkai() else { return };
        let subset = subset_with_cmap(&font, crate::WEB_CHINESE_CHARS).unwrap_or_default();
        // Under a megabyte (the face is 13 MiB), and every character the face has is in it.
        assert!(!subset.is_empty() && subset.len() < 1_000_000, "{} bytes", subset.len());
        let face = FontRef::new(&subset).expect("the subset parses");
        let original = FontRef::new(&font).expect("the font parses");
        let mut kept = 0;
        for c in crate::WEB_CHINESE_CHARS.chars().filter(|c| !c.is_whitespace()) {
            if original.charmap().map(c).is_some() {
                assert!(face.charmap().map(c).is_some(), "{c} is missing from the web face");
                kept += 1;
            }
        }
        assert!(kept > 800, "{kept} characters kept");
    }

    #[test]
    fn a_character_the_font_lacks_is_skipped() {
        let Some(font) = wenkai() else { return };
        let subset = subset_with_cmap(&font, "简\u{1F600}").unwrap_or_default();
        let face = FontRef::new(&subset).expect("the subset parses");
        assert!(face.charmap().map('简').is_some());
        assert!(face.charmap().map('\u{1F600}').is_none());
        assert!(subset_with_cmap(&font, "\u{1F600}").is_err());
    }
}
