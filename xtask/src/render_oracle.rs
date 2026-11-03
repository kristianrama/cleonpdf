//! `cargo xtask render-oracle`: how close CleonPDF's page images are to other renderers'.
//!
//! Each fixture is a PDF page written by hand here (never by the writer under test) that draws one
//! kind of thing: text in the standard fonts, rotated and scaled text, fills and strokes, dashes,
//! curves, clipping, transparency, shadings and an inline image. Every page is rendered at 72 dpi
//! by `cleonpdf-cli` (the `page_render` tool, so the app's own path), by MuPDF (`mutool draw`) and
//! by Poppler (`pdftoppm`), both run as external oracle processes and never linked (AGENTS.md §1.3).
//!
//! The images are compared as luma, averaged over 4 × 4 pixel blocks so that anti-aliasing and
//! hinting differences between renderers do not count. Two numbers per pair:
//! - **mean**: the mean absolute difference over all blocks, 0 (identical) to 255;
//! - **bad**: the fraction of blocks that differ by more than [`BLOCK_LIMIT`].
//!
//! The two oracles are compared with each other too, as the noise floor: two good renderers do not
//! agree exactly. A fixture passes when ours is no further from the nearer oracle than
//! [`MEAN_LIMIT`] and [`BAD_LIMIT`] allow. The limits were set from a first run, not chosen in
//! advance: on the nine built-in fixtures ours is at most 1.03 (mean) and 1.1% (bad) from the
//! nearer oracle, the oracles are at most 1.09 and 1.3% from each other, and the limits are about
//! 2.4 times the first. Shifting our image by one pixel (a one-point error in every glyph) takes
//! dense text to 5.3 / 5.8%, and by two pixels takes every fixture with text or strokes over the
//! bad-block limit, so a displacement of that size does not pass.
//!
//! Nothing here is Acrobat: MuPDF and Poppler are not the reference renderer. This is a regression
//! and sanity check against two independent renderers; Acrobat captures stay a hand-made, local,
//! clean-room step (CLAUDE.md).
//!
//! ```text
//! cargo xtask render-oracle [--dir DIR] [--limit N] [--require-all]
//! ```
//!
//! `--dir` compares every PDF in DIR instead of the built-in fixtures (the first page of each).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::json;

use crate::fuzz::build_pdf;
use crate::gates::{release_cli, root};
use crate::interop::{TIMEOUT, run};

/// Render resolution. 72 dpi gives one pixel per point, so every renderer lands on the same size.
const DPI: u32 = 72;

/// Side of the square blocks the images are averaged over.
const BLOCK: usize = 4;

/// A block counts as different when its mean luma differs by more than this.
const BLOCK_LIMIT: f64 = 24.0;

/// A fixture passes when its mean difference to the nearer oracle is at most this ...
const MEAN_LIMIT: f64 = 2.5;

/// ... and no more than this fraction of its blocks differ by more than [`BLOCK_LIMIT`].
const BAD_LIMIT: f64 = 0.025;

/// Whether a distance is within the limits.
fn within(d: (f64, f64)) -> bool {
    d.0 <= MEAN_LIMIT && d.1 <= BAD_LIMIT
}

/// A grey-scale image.
struct Luma {
    w: usize,
    h: usize,
    px: Vec<f64>,
}

/// Decode a PNG into luma, composited over white. `None` when it is not a PNG we can read.
fn decode(bytes: &[u8]) -> Option<Luma> {
    let mut dec = png::Decoder::new(std::io::Cursor::new(bytes));
    dec.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = dec.read_info().ok()?;
    let mut buf = vec![0u8; reader.output_buffer_size()?];
    let info = reader.next_frame(&mut buf).ok()?;
    let (w, h) = (info.width as usize, info.height as usize);
    let channels = info.color_type.samples();
    let data = buf.get(..info.buffer_size())?;
    let mut px = Vec::with_capacity(w.checked_mul(h)?);
    for p in data.chunks_exact(channels) {
        let (rgb, alpha) = match info.color_type {
            png::ColorType::Grayscale => ([p[0]; 3], 255),
            png::ColorType::GrayscaleAlpha => ([p[0]; 3], p[1]),
            png::ColorType::Rgb => ([p[0], p[1], p[2]], 255),
            png::ColorType::Rgba => ([p[0], p[1], p[2]], p[3]),
            png::ColorType::Indexed => return None,
        };
        let a = f64::from(alpha) / 255.0;
        let y = 0.299 * f64::from(rgb[0]) + 0.587 * f64::from(rgb[1]) + 0.114 * f64::from(rgb[2]);
        px.push(y * a + 255.0 * (1.0 - a));
    }
    (px.len() == w * h).then_some(Luma { w, h, px })
}

/// Block means of the top-left `w × h` part of `img` (partial blocks at the edge are dropped).
fn blocks(img: &Luma, w: usize, h: usize) -> Vec<f64> {
    let (bw, bh) = (w / BLOCK, h / BLOCK);
    let mut out = Vec::with_capacity(bw * bh);
    for by in 0..bh {
        for bx in 0..bw {
            let mut sum = 0.0;
            for y in 0..BLOCK {
                let row = (by * BLOCK + y) * img.w + bx * BLOCK;
                sum += img.px.get(row..row + BLOCK).map_or(0.0, |r| r.iter().sum::<f64>());
            }
            out.push(sum / (BLOCK * BLOCK) as f64);
        }
    }
    out
}

/// How far apart two images are: (mean absolute block difference, fraction of blocks over
/// [`BLOCK_LIMIT`]). Images are compared over their common top-left area; `None` when the sizes
/// differ by more than a few pixels (a different page size is a failure, not noise).
fn distance(a: &Luma, b: &Luma) -> Option<(f64, f64)> {
    if a.w.abs_diff(b.w) > 2 || a.h.abs_diff(b.h) > 2 {
        return None;
    }
    let (w, h) = (a.w.min(b.w), a.h.min(b.h));
    let (ba, bb) = (blocks(a, w, h), blocks(b, w, h));
    if ba.is_empty() {
        return None;
    }
    let n = ba.len() as f64;
    let diffs: Vec<f64> = ba.iter().zip(&bb).map(|(x, y)| (x - y).abs()).collect();
    Some((diffs.iter().sum::<f64>() / n, diffs.iter().filter(|d| **d > BLOCK_LIMIT).count() as f64 / n))
}

/// One A4 page drawing `content`, with fonts F1 (Helvetica), F2 (Times), F3 (Courier), the
/// transparency state GS1 and the shadings Sh1 (axial) and Sh2 (radial) in its resources.
fn page(content: &str) -> Vec<u8> {
    let resources = "<< /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> \
         /ExtGState << /GS1 << /ca 0.5 /CA 0.5 >> >> \
         /Shading << /Sh1 << /ShadingType 2 /ColorSpace /DeviceRGB /Coords [0 0 200 0] \
         /Function << /FunctionType 2 /Domain [0 1] /C0 [1 0 0] /C1 [0 0 1] /N 1 >> /Extend [true true] >> \
         /Sh2 << /ShadingType 3 /ColorSpace /DeviceRGB /Coords [100 100 0 100 100 90] \
         /Function << /FunctionType 2 /Domain [0 1] /C0 [1 1 0] /C1 [0 0.4 0] /N 1 >> /Extend [false false] >> >> >>";
    let objs = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [6 0 R] /Count 1 >>".to_string(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Times-Roman >>".to_string(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>".to_string(),
        format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 7 0 R /Resources {resources} >>"),
        format!("<< /Length {} >>\nstream\n{content}\nendstream", content.len() + 1),
    ];
    build_pdf(&objs.iter().map(String::as_str).collect::<Vec<_>>(), "/Root 1 0 R")
}

/// The built-in fixtures: name and PDF bytes.
fn fixtures() -> Vec<(&'static str, Vec<u8>)> {
    let mut text = String::new();
    for (i, size) in [8, 10, 12, 14, 18, 24, 36].into_iter().enumerate() {
        let y = 800 - 30 * i;
        text += &format!("BT /F1 {size} Tf 40 {y} Td (Hamburgefonstiv {size} pt Helvetica) Tj ET\n");
    }
    text += "BT /F2 14 Tf 40 580 Td (The quick brown fox jumps over the lazy dog. Times Roman 14.) Tj ET\n";
    text += "BT /F3 12 Tf 40 550 Td (The quick brown fox 0123456789 Courier 12.) Tj ET\n";

    let mut moved = String::new();
    moved += "BT /F1 20 Tf 0.866 0.5 -0.5 0.866 80 600 Tm (Rotated thirty degrees) Tj ET\n";
    moved += "BT /F1 20 Tf 0 1 -1 0 300 400 Tm (Rotated ninety degrees) Tj ET\n";
    moved += "BT /F1 18 Tf 150 Tz 40 340 Td (Horizontal scaling 150 percent) Tj ET\n";
    moved += "BT /F1 18 Tf 60 Tz 40 310 Td (Horizontal scaling 60 percent) Tj ET\n";
    moved += "BT /F1 18 Tf 3 Tc 40 280 Td (Character spacing three) Tj ET\n";
    moved += "BT /F1 18 Tf 12 Tw 40 250 Td (Word spacing twelve here) Tj ET\n";
    moved += "BT /F1 40 Tf 1 Tr 1 w 40 190 Td (Stroked) Tj ET\n";
    moved += "BT /F1 40 Tf 2 Tr 0.5 0.8 1 rg 1 0 0 RG 1 w 40 130 Td (Both) Tj ET\n";
    moved += "BT /F1 18 Tf 0 Tr 7 Ts 40 90 Td (Rise) Tj -7 Ts ( and fall) Tj ET\n";

    let mut paint = String::new();
    paint += "1 0 0 rg 40 700 100 60 re f 0 0.6 0 rg 160 700 100 60 re f 0 0 1 rg 280 700 100 60 re f\n";
    paint += "0 1 1 0 k 40 620 100 60 re f 1 0 1 0 k 160 620 100 60 re f 0 0 0 0.5 k 280 620 100 60 re f\n";
    paint += "0.2 g 400 620 100 60 re f 0.7 g 400 700 100 60 re f\n";
    paint += "0 0 0 RG 1 w 40 580 m 540 580 l S 4 w 40 560 m 540 560 l S 12 w 40 530 m 540 530 l S\n";
    paint += "4 w [10 6] 0 d 40 500 m 540 500 l S [2 4] 0 d 40 480 m 540 480 l S [20 5 2 5] 3 d 40 460 m 540 460 l S [] 0 d\n";
    paint += "10 w 0 J 60 400 m 60 440 l S 1 J 100 400 m 100 440 l S 2 J 140 400 m 140 440 l S 0 J\n";
    paint += "10 w 0 j 200 400 m 230 440 l 260 400 l S 1 j 300 400 m 330 440 l 360 400 l S 2 j 400 400 m 430 440 l 460 400 l S 0 j 1 w\n";
    paint += "0.9 0.5 0.1 rg 0 0 0 RG 3 w 60 300 120 70 re B 0.4 g 220 300 m 340 300 l 280 370 l h B\n";

    let mut curves = String::new();
    curves += "0.8 0.2 0.2 rg 0 0 0 RG 2 w 100 700 m 100 755 145 800 200 800 c 255 800 300 755 300 700 c 300 645 255 600 200 600 c 145 600 100 645 100 700 c b\n";
    curves += "0.2 0.3 0.8 rg 350 600 m 400 800 450 600 500 800 c 540 700 560 650 520 600 c f\n";
    curves += "0 0 0 RG 1 w 40 500 m 140 420 220 580 320 480 c 380 420 450 540 540 460 c S\n";
    curves += "0.1 0.6 0.3 rg 150 250 m 250 250 l 170 310 l 200 190 l 230 310 l h f*\n";
    curves += "0.1 0.3 0.6 rg 350 250 m 450 250 l 370 310 l 400 190 l 430 310 l h f\n";

    let mut clip = String::new();
    clip += "q 200 600 m 200 655 245 700 300 700 c 355 700 400 655 400 600 c 400 545 355 500 300 500 c 245 500 200 545 200 600 c W n\n";
    for i in 0..20 {
        clip += &format!("{} {} {} rg 180 {} 240 8 re f\n", if i % 2 == 0 { 1 } else { 0 }, 0.2, if i % 2 == 0 { 0 } else { 1 }, 490 + i * 10);
    }
    clip += "Q 0 0 0 rg BT /F1 14 Tf 40 450 Td (Clipped to a circle) Tj ET\n";

    let mut alpha = String::new();
    alpha += "1 0 0 rg 100 600 200 150 re f /GS1 gs 0 0 1 rg 200 550 200 150 re f 0 0.7 0 rg 150 500 200 150 re f\n";
    alpha += "BT /F1 60 Tf 0 g 80 400 Td (Overlap) Tj ET\n";

    let axial = "q 40 600 300 150 re W n 1 0 0 1 40 0 cm /Sh1 sh Q q 0.8 0 0 0.8 300 300 cm /Sh2 sh Q\n".to_string();
    // A 4 x 4 RGB inline image, scaled up to 200 pt.
    let mut hex = String::new();
    for y in 0..4 {
        for x in 0..4 {
            hex += &format!("{:02x}{:02x}{:02x}", x * 80, y * 80, 255 - (x + y) * 40);
        }
    }
    let image = format!("q 200 0 0 200 100 500 cm BI /W 4 /H 4 /CS /RGB /BPC 8 /F /AHx ID {hex}> EI Q\n");

    let mut dense = String::new();
    for i in 0..60 {
        dense += &format!(
            "BT /F2 10 Tf 40 {} Td (Line {i}: pack my box with five dozen liquor jugs and sphinx of black quartz judge my vow.) Tj ET\n",
            800 - 12 * i
        );
    }

    vec![
        ("text-sizes", page(&text)),
        ("text-moved", page(&moved)),
        ("fills-strokes", page(&paint)),
        ("curves", page(&curves)),
        ("clip", page(&clip)),
        ("alpha", page(&alpha)),
        ("shadings", page(&axial)),
        ("inline-image", page(&image)),
        ("dense-text", page(&dense)),
    ]
}

/// Render page 1 of `pdf` with CleonPDF into `out`.
fn ours(cli: &Path, pdf: &Path, out: &Path, dir: &Path) -> Result<()> {
    let steps = json!([
        { "tool": "doc_open", "args": { "path": pdf.file_name().and_then(|n| n.to_str()).unwrap_or("") } },
        { "tool": "page_render", "args": { "doc": 1, "page": 1, "dpi": DPI }, "out": out.file_name().and_then(|n| n.to_str()).unwrap_or("") },
    ]);
    let script = dir.join("steps.json");
    std::fs::write(&script, steps.to_string())?;
    let o = run(Command::new(cli).current_dir(dir).args(["run", "--root"]).arg(dir).arg("--script").arg(&script), TIMEOUT)
        .context("cleonpdf-cli did not finish")?;
    if o.code != Some(0) {
        bail!("{}", o.stderr.trim());
    }
    Ok(())
}

/// Render page 1 with MuPDF.
fn mupdf(pdf: &Path, out: &Path) -> Option<()> {
    let o = run(Command::new("mutool").args(["draw", "-q", "-r"]).arg(DPI.to_string()).arg("-o").arg(out).arg(pdf).arg("1"), TIMEOUT)?;
    (o.code == Some(0) && out.exists()).then_some(())
}

/// Render page 1 with Poppler.
fn poppler(pdf: &Path, out: &Path) -> Option<()> {
    let stem = out.with_extension("");
    let o = run(
        Command::new("pdftoppm").args(["-r"]).arg(DPI.to_string()).args(["-png", "-f", "1", "-l", "1", "-singlefile"]).arg(pdf).arg(&stem),
        TIMEOUT,
    )?;
    (o.code == Some(0) && out.exists()).then_some(())
}

fn load(path: &Path) -> Option<Luma> {
    decode(&std::fs::read(path).ok()?)
}

pub fn run_cmd(args: &[String]) -> Result<()> {
    let arg = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let limit: usize = arg("--limit").and_then(|v| v.parse().ok()).unwrap_or(usize::MAX);
    let require_all = args.iter().any(|a| a == "--require-all");
    let have = |tool: &str, flag: &str| Command::new(tool).arg(flag).output().is_ok();
    let (has_mupdf, has_poppler) = (have("mutool", "-v"), have("pdftoppm", "-v"));
    if !has_mupdf && !has_poppler {
        bail!("no oracle installed: install mupdf-tools and/or poppler-utils");
    }
    if require_all && !(has_mupdf && has_poppler) {
        bail!("both mutool and pdftoppm are needed (--require-all)");
    }
    let status = Command::new("cargo").args(["build", "--release", "-p", "cleonpdf-cli"]).current_dir(root()).status()?;
    if !status.success() {
        bail!("cargo build failed");
    }
    let cli = release_cli();
    let work = root().join("render-oracle-out");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work)?;

    let mut inputs: Vec<(String, PathBuf)> = Vec::new();
    if let Some(dir) = arg("--dir") {
        let mut files: Vec<PathBuf> =
            std::fs::read_dir(&dir)?.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "pdf")).collect();
        files.sort();
        for f in files.into_iter().take(limit) {
            let name = f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let copy = work.join(format!("in-{}", inputs.len()));
            std::fs::create_dir_all(&copy)?;
            let dest = copy.join("in.pdf");
            std::fs::copy(&f, &dest)?;
            inputs.push((name, dest));
        }
    } else {
        for (name, bytes) in fixtures().into_iter().take(limit) {
            let copy = work.join(name);
            std::fs::create_dir_all(&copy)?;
            let dest = copy.join("in.pdf");
            std::fs::write(&dest, bytes)?;
            inputs.push((name.to_string(), dest));
        }
    }

    println!("{:<28} {:>14} {:>14} {:>14}   verdict", "fixture", "ours~mupdf", "ours~poppler", "mupdf~poppler");
    println!("{:<28} {:>14} {:>14} {:>14}", "", "mean / bad", "mean / bad", "mean / bad");
    let (mut failed, mut compared) = (0usize, 0usize);
    let fmt = |d: Option<(f64, f64)>| d.map_or_else(|| "n/a".to_string(), |(m, b)| format!("{m:5.2} / {:4.1}%", b * 100.0));
    for (name, pdf) in &inputs {
        let Some(dir) = pdf.parent() else { continue };
        let (o, m, p) = (dir.join("ours.png"), dir.join("mupdf.png"), dir.join("poppler.png"));
        if let Err(e) = ours(&cli, pdf, &o, dir) {
            println!("{name:<28} CleonPDF could not render: {}", e.to_string().lines().next().unwrap_or(""));
            failed += 1;
            continue;
        }
        let ours_img = load(&o);
        let mu = if has_mupdf { mupdf(pdf, &m).and_then(|()| load(&m)) } else { None };
        let po = if has_poppler { poppler(pdf, &p).and_then(|()| load(&p)) } else { None };
        let Some(ours_img) = ours_img else {
            println!("{name:<28} CleonPDF wrote no readable image");
            failed += 1;
            continue;
        };
        let d_mu = mu.as_ref().and_then(|x| distance(&ours_img, x));
        let d_po = po.as_ref().and_then(|x| distance(&ours_img, x));
        let d_oo = match (&mu, &po) {
            (Some(a), Some(b)) => distance(a, b),
            _ => None,
        };
        // Compared against whichever oracle is closer; an oracle that could not render the file
        // (or drew a different page size) does not count against us.
        let best = [d_mu, d_po].into_iter().flatten().min_by(|a, b| a.0.total_cmp(&b.0));
        let verdict = match best {
            None => "skipped (no oracle drew it)".to_string(),
            Some(d) if within(d) => {
                compared += 1;
                "ok".to_string()
            }
            Some((mean, bad)) => {
                compared += 1;
                failed += 1;
                format!("FAIL (mean {mean:.2} > {MEAN_LIMIT} or bad {:.1}% > {:.0}%)", bad * 100.0, BAD_LIMIT * 100.0)
            }
        };
        println!("{name:<28} {:>14} {:>14} {:>14}   {verdict}", fmt(d_mu), fmt(d_po), fmt(d_oo));
    }
    println!("render-oracle: {compared} compared, {failed} over the limit; images in render-oracle-out/");
    if failed > 0 {
        bail!("{failed} fixture(s) over the limit");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flat(w: usize, h: usize, v: f64) -> Luma {
        Luma { w, h, px: vec![v; w * h] }
    }

    #[test]
    fn identical_images_are_at_distance_zero() {
        assert_eq!(distance(&flat(40, 40, 120.0), &flat(40, 40, 120.0)), Some((0.0, 0.0)));
    }

    #[test]
    fn a_uniform_shift_is_the_mean_and_counts_as_bad_only_past_the_limit() {
        let (mean, bad) = distance(&flat(40, 40, 100.0), &flat(40, 40, 110.0)).unwrap();
        assert!((mean - 10.0).abs() < 1e-9 && bad == 0.0);
        let (mean, bad) = distance(&flat(40, 40, 100.0), &flat(40, 40, 140.0)).unwrap();
        assert!((mean - 40.0).abs() < 1e-9 && bad == 1.0);
    }

    #[test]
    fn a_different_page_size_is_not_noise() {
        assert!(distance(&flat(40, 40, 0.0), &flat(60, 40, 0.0)).is_none());
        assert!(distance(&flat(40, 40, 0.0), &flat(41, 39, 0.0)).is_some());
    }

    #[test]
    fn an_image_smaller_than_a_block_has_no_distance() {
        assert!(distance(&flat(3, 3, 0.0), &flat(3, 3, 0.0)).is_none());
    }

    #[test]
    fn one_changed_block_is_one_block_in_the_fraction() {
        let a = flat(8, 8, 255.0);
        let mut b = flat(8, 8, 255.0);
        for y in 0..4 {
            for x in 0..4 {
                b.px[y * 8 + x] = 0.0;
            }
        }
        let (mean, bad) = distance(&a, &b).unwrap();
        assert!((mean - 63.75).abs() < 1e-9 && (bad - 0.25).abs() < 1e-9);
    }

    #[test]
    fn a_one_pixel_shift_of_fine_detail_is_over_the_limit() {
        // Vertical lines one pixel wide every three pixels, like a dense page of text.
        let lines = |shift: usize| {
            let (w, h) = (60, 40);
            let px = (0..w * h).map(|i| if (i % w + shift).is_multiple_of(3) { 0.0 } else { 255.0 }).collect();
            Luma { w, h, px }
        };
        assert!(within(distance(&lines(0), &lines(0)).unwrap()));
        assert!(!within(distance(&lines(0), &lines(1)).unwrap()), "{:?}", distance(&lines(0), &lines(1)));
    }

    #[test]
    fn rgba_is_composited_over_white() {
        let mut bytes = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut bytes, 1, 1);
            enc.set_color(png::ColorType::Rgba);
            enc.set_depth(png::BitDepth::Eight);
            let mut w = enc.write_header().unwrap();
            w.write_image_data(&[0, 0, 0, 0]).unwrap();
        }
        let img = decode(&bytes).unwrap();
        assert!((img.px[0] - 255.0).abs() < 1e-9, "transparent black over white is white");
    }

    #[test]
    fn garbage_is_not_an_image() {
        assert!(decode(b"not a png").is_none());
    }

    #[test]
    fn every_fixture_parses_as_a_pdf() {
        for (name, bytes) in fixtures() {
            let doc = lopdf::Document::load_mem(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(doc.get_pages().len(), 1, "{name}");
        }
    }
}
