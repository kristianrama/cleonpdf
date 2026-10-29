//! Accented letters built from two glyphs.
//!
//! TeX (and the PDFs made from its output) draw `è` as a spacing grave accent and an `e` laid
//! over it, because Computer Modern has no `è` glyph. Text extraction has to put the two back
//! together or a search for "perché" finds nothing. This is the table for that; deciding
//! whether the accent really sits on the letter (it overlaps it) is the caller's job.

/// Per accent: the spacing characters it appears as, then the letters it can sit on and what
/// each makes (same order, same count).
const ACCENTS: &[(&str, &str, &str)] = &[
    // grave
    ("`\u{02CB}", "AEIOUaeiou", "ÀÈÌÒÙàèìòù"),
    // acute
    ("´\u{02CA}", "AEIOUYaeiouy", "ÁÉÍÓÚÝáéíóúý"),
    // circumflex
    ("^\u{02C6}", "AEIOUaeiou", "ÂÊÎÔÛâêîôû"),
    // diaeresis
    ("¨", "AEIOUaeiouy", "ÄËÏÖÜäëïöüÿ"),
    // tilde
    ("~\u{02DC}", "ANOano", "ÃÑÕãño"),
    // ring above
    ("\u{02DA}", "Aa", "Åå"),
    // cedilla
    ("¸", "Cc", "Çç"),
    // caron
    ("\u{02C7}", "CDENRSTZcdenrstz", "ČĎĚŇŘŠŤŽčďěňřšťž"),
    // breve
    ("\u{02D8}", "AGUagu", "ĂĞŬăğŭ"),
    // dot above
    ("\u{02D9}", "CEGZcegz", "ĊĖĠŻċėġż"),
    // macron
    ("¯\u{02C9}", "AEIOUaeiou", "ĀĒĪŌŪāēīōū"),
];

/// Whether `c` is a spacing accent that [`compose_accent`] can use.
#[must_use]
pub fn is_spacing_accent(c: char) -> bool {
    ACCENTS.iter().any(|(accents, _, _)| accents.contains(c))
}

/// The letter that the spacing accent `accent` makes over `base`, if there is one.
///
/// A dotless `ı` (what TeX puts under an accent so the dot does not show) counts as `i`.
#[must_use]
pub fn compose_accent(accent: char, base: char) -> Option<char> {
    let base = if base == '\u{0131}' { 'i' } else { base };
    let (_, letters, made) = ACCENTS.iter().find(|(accents, _, _)| accents.contains(accent))?;
    let at = letters.chars().position(|c| c == base)?;
    made.chars().nth(at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_row_pairs_each_letter_with_its_accented_form() {
        for (accents, letters, made) in ACCENTS {
            assert!(!accents.is_empty());
            assert_eq!(letters.chars().count(), made.chars().count(), "{accents}");
        }
    }

    #[test]
    fn the_accents_of_italian_french_and_spanish_compose() {
        for (accent, base, want) in
            [('`', 'e', 'è'), ('`', 'a', 'à'), ('´', 'e', 'é'), ('´', 'E', 'É'), ('¨', 'u', 'ü'), ('^', 'o', 'ô'), ('~', 'n', 'ñ'), ('¸', 'c', 'ç')]
        {
            assert_eq!(compose_accent(accent, base), Some(want), "{accent}{base}");
        }
        // TeX puts a dotless i under the accent.
        assert_eq!(compose_accent('`', '\u{0131}'), Some('ì'));
        assert_eq!(compose_accent('´', '\u{0131}'), Some('í'));
    }

    #[test]
    fn what_is_not_an_accented_letter_does_not_compose() {
        assert_eq!(compose_accent('`', 'x'), None);
        assert_eq!(compose_accent('`', ' '), None);
        assert_eq!(compose_accent('a', 'e'), None);
        assert!(is_spacing_accent('`') && is_spacing_accent('´') && !is_spacing_accent('e'));
    }
}
