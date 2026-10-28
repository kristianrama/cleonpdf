//! Embeds the fonts of the optional craft-fonts build input (`CRAFT_FONTS_DIR`) as `CRAFT_FONTS`.
//! The recipe is craft-fonts' `docs/integration.md`; unset, `CRAFT_FONTS` is empty. It only reads
//! the local checkout (no network). On wasm32 it embeds only the UI faces (BIZ UDPGothic Regular
//! and any `Arab`, `Telu`, `Hebr` or `Thai` face), to keep the web build within hosting limits (Cloudflare Pages:
//! 25 MiB per file). Native builds also embed craft-fonts' opt-in Simplified Chinese manifest
//! (`fonts/simplified-chinese-manifest.txt`, LXGW WenKai Lite), which craft-fonts keeps out of
//! its default manifest and says must never reach a wasm build.

use std::fmt::Write as _;
use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-env-changed=CRAFT_FONTS_DIR");
    println!("cargo::rerun-if-env-changed=CRAFT_FONTS_REQUIRED");
    let mut src = String::from("pub static CRAFT_FONTS: &[CraftFont] = &[\n");
    if let Some(dir) = std::env::var_os("CRAFT_FONTS_DIR").map(PathBuf::from) {
        match craft_fonts(&dir) {
            Ok(entries) => src.push_str(&entries),
            Err(e) if std::env::var_os("CRAFT_FONTS_REQUIRED").is_some() => {
                println!("cargo::error=CRAFT_FONTS_DIR={}: {e}", dir.display());
            }
            Err(e) => println!("cargo::warning=building without craft-fonts: CRAFT_FONTS_DIR={}: {e}", dir.display()),
        }
    }
    src.push_str("];\n");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap_or_default()).join("craft_fonts.rs");
    if let Err(e) = std::fs::write(&out, src) {
        println!("cargo::error=writing {}: {e}", out.display());
    }
}

/// Family-name prefixes of the faces AGENTS.md §1.1 forbids: Adobe's Source families and Noto
/// CJK, which is Source Han under another name. The test in `src/craft.rs` has the same list.
const BARRED_FAMILIES: [&str; 5] = ["Source Han", "Source Serif", "Source Sans", "Noto Sans CJK", "Noto Serif CJK"];

/// craft-fonts' opt-in, native-only Simplified Chinese manifest, same format as the default one.
const CHINESE_MANIFEST: &str = "fonts/simplified-chinese-manifest.txt";

/// One `CraftFont { .. }` initialiser per manifest line: the default manifest, then (native
/// builds only) the Simplified Chinese one.
fn craft_fonts(dir: &std::path::Path) -> Result<String, String> {
    let wasm = std::env::var("CARGO_CFG_TARGET_ARCH").is_ok_and(|a| a == "wasm32");
    let has = |scripts: &str, script: &str| scripts.split(',').any(|s| s.trim() == script);
    let mut out = manifest_fonts(dir, "fonts/manifest.txt", &|family, style, scripts| {
        // Arabic, Telugu, Hebrew and Thai interface faces are small, so the web build keeps them too.
        let web_face =
            (family == "BIZ UDPGothic" && style == "Regular") || ["Arab", "Telu", "Hebr", "Thai"].iter().any(|script| has(scripts, script));
        !wasm || web_face
    })?;
    // Never on wasm: the face is 13 MiB, over the web build's budget (craft-fonts' own rule).
    if !wasm {
        let manifest = dir.join(CHINESE_MANIFEST);
        println!("cargo::rerun-if-changed={}", manifest.display());
        if manifest.is_file() {
            out.push_str(&manifest_fonts(dir, CHINESE_MANIFEST, &|_, _, _| true)?);
        } else if std::env::var_os("CRAFT_FONTS_REQUIRED").is_some() {
            return Err(format!("{}: missing, so the interface has no Simplified Chinese face", manifest.display()));
        } else {
            println!("cargo::warning=craft-fonts has no {CHINESE_MANIFEST}: Chinese interface text may show missing-glyph boxes");
        }
    }
    Ok(out)
}

/// The initialisers for the faces of the manifest `rel` (relative to `dir`) that `keep` accepts
/// (it is given family, style and the comma-separated scripts).
fn manifest_fonts(dir: &std::path::Path, rel: &str, keep: &dyn Fn(&str, &str, &str) -> bool) -> Result<String, String> {
    let manifest = dir.join(rel);
    println!("cargo::rerun-if-changed={}", manifest.display());
    let text = std::fs::read_to_string(&manifest).map_err(|e| format!("{}: {e}", manifest.display()))?;
    let mut out = String::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let f: Vec<&str> = line.split(" | ").map(str::trim).collect();
        let [family, style, file, scripts, ..] = f.as_slice() else {
            return Err(format!("malformed manifest line: {line}"));
        };
        // AGENTS.md §1.1 bars Adobe's type designs whatever their licence, so a checkout that
        // carries one (craft-fonts has Noto Sans CJK, which is Source Han) never embeds it.
        if BARRED_FAMILIES.iter().any(|barred| family.starts_with(barred)) {
            println!("cargo::warning=craft-fonts: not embedding {family} {style} (AGENTS.md §1.1)");
            continue;
        }
        if !keep(family, style, scripts) {
            continue;
        }
        let path = dir.join(file).canonicalize().map_err(|e| format!("{file}: {e}"))?;
        println!("cargo::rerun-if-changed={}", path.display());
        let scripts: Vec<String> = scripts.split(',').map(|s| format!("{:?}", s.trim())).collect();
        let _ = writeln!(
            out,
            "    CraftFont {{ family: {family:?}, style: {style:?}, scripts: &[{}], bytes: include_bytes!({:?}) }},",
            scripts.join(", "),
            path.display().to_string(),
        );
    }
    Ok(out)
}
