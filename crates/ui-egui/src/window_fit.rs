//! Fit the first window onto its monitor.
//!
//! A first start (no saved window) asks for 1440 × 920 points. Windows puts a new window at a
//! cascade position, so on a 1920 × 1080 screen the bottom of the window ended under the taskbar,
//! and on a laptop at 125 % (1536 × 864 points) the window is taller than the screen. The app
//! creates that window centred on the primary monitor (eframe's `centered`), so on its first
//! frames [`step`] shrinks it to the monitor, less room for the system's bars, and centres it
//! there ([`crate::CleonPdfApp::fit_window_on_start`]). Later starts restore the window the user
//! left.

use egui::{Pos2, Rect, Vec2, pos2, vec2};

/// Room kept for the system's bars: the macOS menu bar or a GNOME top bar at the top, the
/// Windows taskbar (48 points) or a dock at the bottom, and a margin all round.
const TOP: f32 = 40.0;
const BOTTOM: f32 = 64.0;
const SIDE: f32 = 24.0;

/// How many frames to wait for the platform to report the window's place before giving up.
const TRIES: u8 = 30;

/// A first start's window still to fit.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Pending {
    /// Frames left to wait for the platform to report the window's place.
    tries: u8,
    /// The zoom factor in the previous frame.
    zoom: Option<f32>,
}

impl Default for Pending {
    fn default() -> Self {
        Self { tries: TRIES, zoom: None }
    }
}

/// One frame of fitting the window: once the platform reports where the window is, move (and if
/// need be shrink) it, once, and drop `pending`. Does nothing for a maximized or full-screen
/// window, or one that fits.
pub(crate) fn step(pending: &mut Option<Pending>, ctx: &egui::Context) {
    let Some(p) = pending.as_mut() else { return };
    let (outer, inner, monitor, whole_screen) = ctx.input(|i| {
        let v = i.viewport();
        (v.outer_rect, v.inner_rect, v.monitor_size, v.maximized == Some(true) || v.fullscreen == Some(true))
    });
    // In the frame after a zoom change, egui-winit measured the window in the previous zoom's
    // points while the commands use the new one: wait for a frame with the zoom unchanged.
    let zoom = ctx.zoom_factor();
    let zoom_changed = p.zoom.is_some_and(|z| z != zoom);
    p.zoom = Some(zoom);
    let (Some(outer), Some(inner), Some(monitor)) = (outer, inner, monitor) else {
        p.tries = p.tries.saturating_sub(1);
        if p.tries == 0 {
            *pending = None;
        }
        return;
    };
    if zoom_changed && !whole_screen {
        return;
    }
    *pending = None;
    if whole_screen {
        return;
    }
    if let Some((size, pos)) = fit(outer, inner, monitor) {
        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size));
        ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(pos));
    }
}

/// Where the window should go: its new inner size and outer position, in points, or `None` when
/// it already fits (or a number is unusable). `outer` and `inner` are the window with and without
/// its frame, `monitor` the size of the monitor it is on; all in points, the monitor's top left
/// at the origin.
pub(crate) fn fit(outer: Rect, inner: Rect, monitor: Vec2) -> Option<(Vec2, Pos2)> {
    let finite = [outer.min, outer.max, inner.min, inner.max].iter().all(|p| p.is_finite()) && monitor.is_finite();
    if !finite || outer.width() <= 0.0 || outer.height() <= 0.0 {
        return None;
    }
    let area = Rect::from_min_max(pos2(SIDE, TOP), pos2(monitor.x - SIDE, monitor.y - BOTTOM));
    // A monitor too small to keep the margins: leave the window to the system.
    if area.width() <= 0.0 || area.height() <= 0.0 || area.contains_rect(outer) {
        return None;
    }
    let frame = (outer.size() - inner.size()).max(Vec2::ZERO);
    let size = outer.size().min(area.size());
    let inner_size = (size - frame).max(vec2(1.0, 1.0));
    Some((inner_size, area.center() - size / 2.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A window of `inner` points with a `title`-point title bar, its outer top left at `at`.
    fn window(at: Pos2, inner: Vec2, title: f32) -> (Rect, Rect) {
        let outer = Rect::from_min_size(at, inner + vec2(0.0, title));
        (outer, Rect::from_min_size(at + vec2(0.0, title), inner))
    }

    #[test]
    fn a_1080p_screen_moves_the_window_up_out_of_the_taskbar() {
        // Where Windows put it: the bottom 103 points below the screen's edge.
        let (outer, inner) = window(pos2(190.0, 183.0), vec2(1440.0, 920.0), 32.0);
        let (size, pos) = fit(outer, inner, vec2(1920.0, 1080.0)).expect("doesn't fit");
        assert_eq!(size, vec2(1440.0, 920.0), "it fits once moved, so it keeps its size");
        assert_eq!(pos, pos2(240.0, 52.0));
        assert!(pos.y + 952.0 <= 1080.0 - 48.0, "above the taskbar");
    }

    #[test]
    fn a_small_screen_shrinks_the_window_and_keeps_the_frame() {
        // A laptop at 125 %: 1536 × 864 points.
        let (outer, inner) = window(pos2(48.0, 0.0), vec2(1440.0, 920.0), 32.0);
        let (size, pos) = fit(outer, inner, vec2(1536.0, 864.0)).expect("too tall");
        assert_eq!(size, vec2(1440.0, 760.0 - 32.0));
        assert_eq!(pos, pos2(24.0 + (1488.0 - 1440.0) / 2.0, 40.0));
        // And a frameless window (the macOS integrated title bar) gets the whole height.
        let (outer, inner) = window(pos2(15.0, 18.0), vec2(1440.0, 920.0), 0.0);
        assert_eq!(fit(outer, inner, vec2(1470.0, 956.0)), Some((vec2(1422.0, 852.0), pos2(24.0, 40.0))));
    }

    #[test]
    fn a_window_that_fits_stays_where_it_is() {
        let (outer, inner) = window(pos2(240.0, 60.0), vec2(1440.0, 920.0), 32.0);
        assert_eq!(fit(outer, inner, vec2(2560.0, 1440.0)), None);
    }

    #[test]
    fn unusable_numbers_change_nothing() {
        let (outer, inner) = window(pos2(0.0, 0.0), vec2(1440.0, 920.0), 32.0);
        assert_eq!(fit(outer, inner, vec2(40.0, 90.0)), None, "monitor smaller than the margins");
        assert_eq!(fit(outer, inner, vec2(f32::NAN, 1080.0)), None);
        assert_eq!(fit(outer, inner, vec2(f32::INFINITY, 1080.0)), None);
        assert_eq!(fit(Rect::NOTHING, inner, vec2(1920.0, 1080.0)), None);
        let nan = Rect::from_min_size(pos2(f32::NAN, 0.0), vec2(10.0, 10.0));
        assert_eq!(fit(nan, inner, vec2(1920.0, 1080.0)), None);
    }

    /// The viewport commands of one frame of [`step`], the window at `at`, 1440 × 920 points
    /// with a 32-point title bar, on a 1920 × 1080 monitor. `None` reports no place.
    fn frame(ctx: &egui::Context, pending: &mut Option<Pending>, at: Option<Pos2>, maximized: bool) -> Vec<egui::ViewportCommand> {
        let mut raw = egui::RawInput::default();
        let v = raw.viewports.entry(egui::ViewportId::ROOT).or_default();
        if let Some(at) = at {
            let (outer, inner) = window(at, vec2(1440.0, 920.0), 32.0);
            (v.outer_rect, v.inner_rect, v.monitor_size) = (Some(outer), Some(inner), Some(vec2(1920.0, 1080.0)));
        }
        v.maximized = Some(maximized);
        let mut out = ctx.run_ui(raw, |ui| step(pending, ui.ctx()));
        // A bare context's first frame uploads the font atlas; nothing paints it here.
        out.textures_delta.clear();
        let commands = out.viewport_output.get(&egui::ViewportId::ROOT).map(|o| o.commands.clone()).unwrap_or_default();
        // egui adds commands of its own (the system theme, on a first frame).
        commands.into_iter().filter(|c| matches!(c, egui::ViewportCommand::InnerSize(_) | egui::ViewportCommand::OuterPosition(_))).collect()
    }

    fn moved_to(y: f32) -> Vec<egui::ViewportCommand> {
        vec![egui::ViewportCommand::InnerSize(vec2(1440.0, 920.0)), egui::ViewportCommand::OuterPosition(pos2(240.0, y))]
    }

    #[test]
    fn a_first_start_moves_the_window_once_its_place_is_known() {
        let ctx = egui::Context::default();
        let mut pending = Some(Pending::default());
        assert!(frame(&ctx, &mut pending, None, false).is_empty(), "no place reported yet");
        assert!(pending.is_some(), "still waiting");
        assert_eq!(frame(&ctx, &mut pending, Some(pos2(190.0, 183.0)), false), moved_to(52.0));
        assert_eq!(pending, None, "once");
        assert!(frame(&ctx, &mut pending, Some(pos2(190.0, 183.0)), false).is_empty());
    }

    #[test]
    fn other_starts_and_maximized_windows_are_left_alone() {
        let ctx = egui::Context::default();
        let mut pending = None;
        assert!(frame(&ctx, &mut pending, Some(pos2(190.0, 183.0)), false).is_empty(), "not a first start");
        let mut pending = Some(Pending::default());
        assert!(frame(&ctx, &mut pending, Some(pos2(0.0, 0.0)), true).is_empty());
        assert_eq!(pending, None);
    }

    #[test]
    fn it_gives_up_when_the_platform_never_says_where_the_window_is() {
        // Wayland reports no window position.
        let ctx = egui::Context::default();
        let mut pending = Some(Pending::default());
        for _ in 0..TRIES {
            assert!(frame(&ctx, &mut pending, None, false).is_empty());
        }
        assert_eq!(pending, None);
    }

    #[test]
    fn it_waits_out_the_frame_after_a_zoom_change() {
        let ctx = egui::Context::default();
        let mut pending = Some(Pending::default());
        assert!(frame(&ctx, &mut pending, None, false).is_empty());
        // The interface size changes (ui_scale::sync); it takes effect in the next frame, whose
        // window rect egui-winit measured with the old zoom.
        ctx.set_zoom_factor(1.25);
        assert!(frame(&ctx, &mut pending, Some(pos2(190.0, 183.0)), false).is_empty());
        assert!(pending.is_some());
        assert_eq!(frame(&ctx, &mut pending, Some(pos2(190.0, 183.0)), false), moved_to(52.0));
    }
}
